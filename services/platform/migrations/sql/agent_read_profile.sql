CREATE SCHEMA zasp_agent_read_v1 AUTHORIZATION zasp_discovery_authority;
-- agent read authority definitions
REVOKE ALL ON SCHEMA zasp_agent_read_v1 FROM PUBLIC;
CREATE TABLE zasp_agent_read_v1.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),name text NOT NULL,checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),parent79 text NOT NULL,parent80 text NOT NULL,temporal text NOT NULL,audit text NOT NULL,identity text NOT NULL,fingerprint text NOT NULL);
ALTER TABLE zasp_agent_read_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_read_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_read_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_read_v1.registration FROM PUBLIC,zasp_discovery_api;
CREATE POLICY authority ON zasp_agent_read_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_read_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE FUNCTION zasp_agent_read_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_agent_read_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_agent_read_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','session-relation',c.oid::regclass::text,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass)
 UNION ALL SELECT concat_ws('|','session-column',a.attrelid,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','session-constraint',k.conrelid,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k WHERE k.conrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass)
 UNION ALL SELECT concat_ws('|','session-index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i WHERE i.indrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass)
 UNION ALL SELECT concat_ws('|','session-trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass) AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_agent_read_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_agent_read_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_agent_read_v1.catalog_ready(c text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_read_v1.registration;manifest_text constant text:=$agent_read_manifest$-- agent read function manifest$agent_read_manifest$;p jsonb;f record;BEGIN
 SELECT * INTO r FROM zasp_agent_read_v1.registration WHERE singleton;
 IF NOT COALESCE(c='-- agent read filter checksum' AND r.checksum=c AND r.name='-- agent read filter name' AND r.parent79='-- agent read parent79' AND r.parent80='-- agent read parent80' AND r.temporal='-- agent read temporal' AND r.audit='-- agent read audit' AND r.identity='-- agent read identity',false) THEN RETURN false;END IF;
 IF NOT zasp_authorization79.ready(r.parent79) OR NOT zasp_authorization80.ready(r.parent80) OR NOT zasp_authorization80_temporal.ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE singleton AND checksum=r.temporal) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- agent read audit mode' AND identity_mode='-- agent read identity mode') OR(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 -- agent read selected parent predicate
 IF NOT public.zasp_inventory_security_ready() OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=14 AND name='typed_inventory_cutover' AND checksum='-- agent read typed14') OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='typed_inventory_cutover_fingerprint' AND value='-- agent read typed14 fingerprint') THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=40 AND name='production_runtime_sessions' AND checksum='-- agent read session40') OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_sessions_fingerprint' AND value='-- agent read session40 fingerprint') OR NOT zasp_authorization80.session_source_readiness(41,'-- agent read session41','-- agent read session41 fingerprint') THEN RETURN false;END IF;
 -- Source41's original summary projection is required, rather than inferred from nonempty fixture rows.
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.zasp_runtime_session_events'::regclass AND tgname='zasp_runtime_session_summary_projection' AND NOT tgisinternal AND tgenabled='O' AND tgtype=29 AND tgnargs=0 AND tgfoid='public.zasp_runtime_session_maintain_summary()'::regprocedure) THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'relations') LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.oid=(p->>'relation')::regclass AND t.relkind='r' AND t.relowner='zasp_discovery_authority'::regrole AND t.relrowsecurity AND t.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) THEN RETURN false;END IF;
  IF(SELECT jsonb_agg(jsonb_build_object('name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'notnull',a.attnotnull) ORDER BY a.attnum) FROM pg_attribute a WHERE a.attrelid=(p->>'relation')::regclass AND a.attnum>0 AND NOT a.attisdropped) IS DISTINCT FROM p->'columns' OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=(p->>'relation')::regclass AND a.attnum>0 AND NOT a.attisdropped AND(a.attacl IS NOT NULL OR a.attidentity<>'' OR a.attgenerated<>'')) THEN RETURN false;END IF;
  IF(SELECT count(*) FROM pg_policy WHERE polrelid=(p->>'relation')::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=(p->>'relation')::regclass AND polname=p->>'policy' AND polcmd='*' AND polpermissive AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;
 END LOOP;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'parents') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>p->>'source' OR f.proowner::regrole::text<>p->>'owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(f.proowner,CASE WHEN(p->>'api')::boolean THEN 'zasp_discovery_api'::regrole::oid WHEN p->>'owner'='zasp_inventory_authority' THEN 'zasp_discovery_authority'::regrole::oid ELSE f.proowner END)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR((p->>'api')::boolean AND NOT has_function_privilege('zasp_discovery_api',f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_agent_read_v1'::regnamespace)<>7 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_read_v1'::regnamespace AND relkind='r')<>1 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_agent_read_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;

 -- Only the table's actual composite and implicit array belong to this profile.
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_agent_read_v1'::regnamespace)<>2 OR NOT EXISTS(
  SELECT 1 FROM pg_class r JOIN pg_type c ON c.oid=r.reltype JOIN pg_type a ON a.oid=c.typarray
  WHERE r.oid='zasp_agent_read_v1.registration'::regclass AND c.typnamespace=r.relnamespace AND a.typnamespace=r.relnamespace
  AND c.typname='registration' AND a.typname='_registration' AND c.typowner='zasp_discovery_authority'::regrole AND a.typowner='zasp_discovery_authority'::regrole
  AND c.typacl IS NULL AND a.typacl IS NULL AND c.typtype='c' AND c.typcategory='C' AND c.typrelid=r.oid AND c.typelem=0
  AND a.typtype='b' AND a.typcategory='A' AND a.typrelid=0 AND a.typelem=c.oid AND a.typarray=0
  AND c.typisdefined AND a.typisdefined AND c.typbasetype=0 AND a.typbasetype=0 AND NOT c.typnotnull AND NOT a.typnotnull
  AND c.typndims=0 AND a.typndims=0 AND c.typdefaultbin IS NULL AND a.typdefaultbin IS NULL AND c.typdefault IS NULL AND a.typdefault IS NULL
 ) THEN RETURN false;END IF;
 -- These fixed PostgreSQL17 namespace catalogs have no profile objects.
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_agent_read_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_agent_read_v1'::regnamespace) THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'own') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.provolatile<>'s' OR f.proparallel<>'u' OR f.proisstrict OR f.lanname NOT IN('sql','plpgsql') OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(replace(replace(f.prosrc,c,'-- agent read filter '||'checksum'),manifest_text,'-- agent read function '||'manifest'),'UTF8'),'sha256'),'hex')<>p->>'source' THEN RETURN false;END IF;
  IF f.prokind<>'f' OR f.proretset OR f.proleakproof OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL
  OR f.prorettype<>CASE f.proname WHEN 'fingerprint' THEN 'text'::regtype WHEN 'detail' THEN 'jsonb'::regtype WHEN 'capabilities' THEN 'jsonb'::regtype WHEN 'relationships' THEN 'jsonb'::regtype WHEN 'sessions' THEN 'jsonb'::regtype ELSE 'boolean'::regtype END
  OR f.lanname<>CASE WHEN f.proname IN('fingerprint','caller_ready') THEN 'sql' ELSE 'plpgsql' END
  OR f.proargnames IS DISTINCT FROM CASE f.proname WHEN 'fingerprint' THEN NULL::text[] WHEN 'detail' THEN ARRAY['o','w','e','agent','c'] WHEN 'capabilities' THEN ARRAY['o','w','e','agent','a','n','c'] WHEN 'relationships' THEN ARRAY['o','w','e','agent','a','n','c'] WHEN 'sessions' THEN ARRAY['o','w','e','agent','a','n','c'] ELSE ARRAY['c'] END THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(f.proowner,CASE WHEN f.proname IN('detail','capabilities','relationships','sessions','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE f.proowner END)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR(f.proname IN('detail','capabilities','relationships','sessions','caller_ready') AND NOT has_function_privilege('zasp_discovery_api',f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_read_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE')))) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.oid='zasp_agent_read_v1.registration'::regclass AND t.relowner='zasp_discovery_authority'::regrole AND t.relrowsecurity AND t.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) OR EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_read_v1.registration'::regclass AND attacl IS NOT NULL) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_policy WHERE polrelid='zasp_agent_read_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='zasp_agent_read_v1.registration'::regclass AND polname='authority' AND polcmd='*' AND polpermissive AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;

 IF NOT has_schema_privilege('zasp_discovery_api','zasp_agent_read_v1','USAGE') OR has_schema_privilege('zasp_discovery_api','zasp_agent_read_v1','CREATE') THEN RETURN false;END IF;
 IF(SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute WHERE attrelid='zasp_agent_read_v1.registration'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM ARRAY['singleton','name','checksum','parent79','parent80','temporal','audit','identity','fingerprint'] THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_agent_read_v1.registration'::regclass AND a.attnum>0 AND NOT a.attisdropped AND(NOT a.attnotnull OR a.attidentity<>'' OR a.attgenerated<>'' OR a.attacl IS NOT NULL OR a.atttypid<>CASE WHEN a.attnum=1 THEN 'boolean'::regtype ELSE 'text'::regtype END OR(a.attnum=1 AND pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM 'true') OR(a.attnum>1 AND d.oid IS NOT NULL))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype<>'n')<>3 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated) OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype='c' AND pg_get_expr(conbin,conrelid)='singleton' AND convalidated) OR EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype='n' AND(cardinality(conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=conrelid AND a.attnum=conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype='c')<>2 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_read_v1.registration'::regclass AND contype='c' AND convalidated AND pg_get_expr(conbin,conrelid)=$checksum_expr$(checksum ~ '^[a-f0-9]{64}$'::text)$checksum_expr$) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='zasp_agent_read_v1' AND nspowner='zasp_discovery_authority'::regrole) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_index WHERE indrelid='zasp_agent_read_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid='zasp_agent_read_v1.registration'::regclass AND indisprimary AND indisunique AND indisvalid AND indisready AND indkey::text='1') THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_trigger WHERE tgrelid='zasp_agent_read_v1.registration'::regclass AND NOT tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_agent_read_v1.registration'::regclass AND NOT tgisinternal AND tgname='immutable' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_temporal67.immutable()'::regprocedure) THEN RETURN false;END IF;
 RETURN r.fingerprint=zasp_agent_read_v1.fingerprint();
EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_read_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_agent_read_v1.catalog_ready(c) AND public.zasp_discovery_principal_ready('zasp_discovery_api')
$$;
CREATE FUNCTION zasp_agent_read_v1.detail(o text,w text,e text,agent text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_read_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getAgent'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR agent IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(agent) OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read';END IF;
 IF zasp_authorization80.context()#>>'{path_parameters,id}' IS DISTINCT FROM agent OR NOT COALESCE(zasp_authorization80.allowed(o,w,e,'agent',agent),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read target refused';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.id,v.state,v.product_kind)=(o,w,e,agent,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 RETURN public.zasp_inventory_detail(o,w,e,agent,'agent');
END
$$;
CREATE FUNCTION zasp_agent_read_v1.capabilities(o text,w text,e text,agent text,a text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_read_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getAgentCapabilities'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR agent IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(agent) OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read';END IF;
 IF zasp_authorization80.context()#>>'{path_parameters,id}' IS DISTINCT FROM agent OR NOT COALESCE(zasp_authorization80.allowed(o,w,e,'agent',agent),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read target refused';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.id,v.state,v.product_kind)=(o,w,e,agent,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read page';END IF;
 RETURN public.zasp_inventory_agent_capabilities_page(o,w,e,agent,a,n);
END
$$;
CREATE FUNCTION zasp_agent_read_v1.relationships(o text,w text,e text,agent text,a text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_read_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['getAgentRelationships'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR agent IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(agent) OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read';END IF;
 IF zasp_authorization80.context()#>>'{path_parameters,id}' IS DISTINCT FROM agent OR NOT COALESCE(zasp_authorization80.allowed(o,w,e,'agent',agent),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read target refused';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.id,v.state,v.product_kind)=(o,w,e,agent,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read page';END IF;
 RETURN public.zasp_inventory_agent_relationships_page(o,w,e,agent,a,n);
END
$$;
CREATE FUNCTION zasp_agent_read_v1.sessions(o text,w text,e text,agent text,a text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_read_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAgentSessions'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR agent IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(agent) OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read';END IF;
 IF zasp_authorization80.context()#>>'{path_parameters,id}' IS DISTINCT FROM agent OR NOT COALESCE(zasp_authorization80.allowed(o,w,e,'agent',agent),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent read target refused';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.id,v.state,v.product_kind)=(o,w,e,agent,'active','agent')) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='typed agent missing';END IF;
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent read page';END IF;
 IF a IS NOT NULL AND NOT public.zasp_valid_product_id(a) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent sessions page';END IF;
 WITH candidates AS(
  SELECT summary.id,summary.first_event_at FROM public.zasp_runtime_session_summaries summary
  WHERE(summary.organization_id,summary.workspace_id,summary.environment_id)=(o,w,e)
  AND public.zasp_valid_product_id(summary.id) AND(a IS NULL OR summary.id>a)
  AND EXISTS(SELECT 1 FROM public.zasp_runtime_session_events event WHERE(event.organization_id,event.workspace_id,event.environment_id,event.session_id,event.agent_id)=(o,w,e,summary.id,agent))
  ORDER BY summary.id LIMIT n+1
 ),visible AS(SELECT * FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'agent_id',agent,'started_at',rtrim(rtrim(to_char(first_event_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z') ORDER BY id),'[]'::jsonb),'next_key',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result FROM visible;
 RETURN result;
END
$$;
DO $owners$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_agent_read_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api',f);END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_agent_read_v1 TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_agent_read_v1.detail(text,text,text,text,text),zasp_agent_read_v1.capabilities(text,text,text,text,text,integer,text),zasp_agent_read_v1.relationships(text,text,text,text,text,integer,text),zasp_agent_read_v1.sessions(text,text,text,text,text,integer,text),zasp_agent_read_v1.caller_ready(text) TO zasp_discovery_api;
