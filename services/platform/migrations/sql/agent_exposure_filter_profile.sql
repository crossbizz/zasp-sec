CREATE SCHEMA zasp_agent_exposure_filter_v1 AUTHORIZATION zasp_discovery_authority;
-- exposure authority definitions
REVOKE ALL ON SCHEMA zasp_agent_exposure_filter_v1 FROM PUBLIC;
CREATE TABLE zasp_agent_exposure_filter_v1.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),name text NOT NULL,checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),parent79 text NOT NULL,parent80 text NOT NULL,temporal text NOT NULL,audit text NOT NULL,identity text NOT NULL,fingerprint text NOT NULL);
ALTER TABLE zasp_agent_exposure_filter_v1.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_agent_exposure_filter_v1.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_agent_exposure_filter_v1.registration FORCE ROW LEVEL SECURITY;
REVOKE ALL ON zasp_agent_exposure_filter_v1.registration FROM PUBLIC,zasp_discovery_api;
CREATE POLICY authority ON zasp_agent_exposure_filter_v1.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_agent_exposure_filter_v1.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE FUNCTION zasp_agent_exposure_filter_v1.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 WITH facts(v) AS (
 SELECT concat_ws('|','schema',nspowner,nspacl::text) FROM pg_namespace WHERE nspname='zasp_agent_exposure_filter_v1'
 UNION ALL SELECT concat_ws('|','type',t.oid,t.typname,t.typowner,t.typacl::text,t.typtype,t.typcategory,t.typrelid,t.typelem,t.typarray,t.typbasetype,t.typisdefined,t.typnotnull,t.typndims,t.typcollation,t.typinput,t.typoutput,t.typreceive,t.typsend,t.typmodin,t.typmodout,t.typanalyze,t.typsubscript,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typdelim,t.typdefaultbin::text,t.typdefault) FROM pg_type t WHERE t.typnamespace='zasp_agent_exposure_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_agent_exposure_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','relation',c.relname,c.relkind,c.relowner,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_class c JOIN pg_constraint k ON k.conrelid=c.oid WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','index',i.indexrelid::regclass::text,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace AND NOT t.tgisinternal
 UNION ALL SELECT concat_ws('|','policy',p.polrelid,p.polname,p.polcmd,p.polpermissive,p.polroles::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_agent_exposure_filter_v1'::regnamespace
 ) SELECT encode(public.digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$$;
CREATE FUNCTION zasp_agent_exposure_filter_v1.catalog_ready(c text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE r zasp_agent_exposure_filter_v1.registration;manifest_text constant text:=$exposure_manifest$-- exposure function manifest$exposure_manifest$;p jsonb;f record;BEGIN
 SELECT * INTO r FROM zasp_agent_exposure_filter_v1.registration WHERE singleton;
 IF NOT COALESCE(c='-- exposure filter checksum' AND r.checksum=c AND r.name='-- exposure filter name' AND r.parent79='-- exposure parent79' AND r.parent80='-- exposure parent80' AND r.temporal='-- exposure temporal' AND r.audit='-- exposure audit' AND r.identity='-- exposure identity',false) THEN RETURN false;END IF;
 IF NOT zasp_authorization79.ready(r.parent79) OR NOT zasp_authorization80.ready(r.parent80) OR NOT zasp_authorization80_temporal.ready() OR NOT EXISTS(SELECT 1 FROM zasp_authorization80_temporal.registration WHERE singleton AND checksum=r.temporal) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80.runtime_profile WHERE singleton AND name='canonical61-temporal78-authorization79-80-v1' AND audit_mode='-- exposure audit mode' AND identity_mode='-- exposure identity mode') OR(SELECT count(*) FROM zasp_authorization80.runtime_profile)<>1 THEN RETURN false;END IF;
 -- exposure selected parent predicate
 IF NOT public.zasp_inventory_security_ready() OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=14 AND name='typed_inventory_cutover' AND checksum='-- exposure typed14') OR NOT EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='typed_inventory_cutover_fingerprint' AND value='-- exposure typed14 fingerprint') THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'parents') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF encode(public.digest(convert_to(f.prosrc,'UTF8'),'sha256'),'hex')<>p->>'source' OR f.proowner::regrole::text<>p->>'owner' OR NOT f.prosecdef OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR f.proacl::text IS DISTINCT FROM p->>'acl' THEN RETURN false;END IF;
 END LOOP;
 IF(SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_agent_exposure_filter_v1'::regnamespace)<>6 OR(SELECT count(*) FROM pg_class WHERE relnamespace='zasp_agent_exposure_filter_v1'::regnamespace AND relkind='r')<>1 OR EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='zasp_agent_exposure_filter_v1'::regnamespace AND relkind NOT IN('r','i')) THEN RETURN false;END IF;

 -- Only the table's actual composite and implicit array belong to this profile.
 IF(SELECT count(*) FROM pg_type WHERE typnamespace='zasp_agent_exposure_filter_v1'::regnamespace)<>2 OR NOT EXISTS(
  SELECT 1 FROM pg_class r JOIN pg_type c ON c.oid=r.reltype JOIN pg_type a ON a.oid=c.typarray
  WHERE r.oid='zasp_agent_exposure_filter_v1.registration'::regclass AND c.typnamespace=r.relnamespace AND a.typnamespace=r.relnamespace
  AND c.typname='registration' AND a.typname='_registration' AND c.typowner='zasp_discovery_authority'::regrole AND a.typowner='zasp_discovery_authority'::regrole
  AND c.typacl IS NULL AND a.typacl IS NULL AND c.typtype='c' AND c.typcategory='C' AND c.typrelid=r.oid AND c.typelem=0
  AND a.typtype='b' AND a.typcategory='A' AND a.typrelid=0 AND a.typelem=c.oid AND a.typarray=0
  AND c.typisdefined AND a.typisdefined AND c.typbasetype=0 AND a.typbasetype=0 AND NOT c.typnotnull AND NOT a.typnotnull
  AND c.typndims=0 AND a.typndims=0 AND c.typdefaultbin IS NULL AND a.typdefaultbin IS NULL AND c.typdefault IS NULL AND a.typdefault IS NULL
 ) THEN RETURN false;END IF;
 -- These fixed PostgreSQL17 namespace catalogs have no profile objects.
 IF EXISTS(SELECT 1 FROM pg_operator WHERE oprnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_collation WHERE collnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_conversion WHERE connamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opclass WHERE opcnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_opfamily WHERE opfnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_config WHERE cfgnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_dict WHERE dictnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_parser WHERE prsnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_ts_template WHERE tmplnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_statistic_ext WHERE stxnamespace='zasp_agent_exposure_filter_v1'::regnamespace)
 OR EXISTS(SELECT 1 FROM pg_extension WHERE extnamespace='zasp_agent_exposure_filter_v1'::regnamespace) THEN RETURN false;END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(manifest_text::jsonb->'own') LOOP
  SELECT x.*,l.lanname INTO STRICT f FROM pg_proc x JOIN pg_language l ON l.oid=x.prolang WHERE x.oid=(p->>'signature')::regprocedure;
  IF f.proowner<>'zasp_discovery_authority'::regrole OR NOT f.prosecdef OR f.provolatile<>'s' OR f.proparallel<>'u' OR f.proisstrict OR f.lanname NOT IN('sql','plpgsql') OR f.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public'] OR encode(public.digest(convert_to(replace(replace(f.prosrc,c,'-- exposure filter '||'checksum'),manifest_text,'-- exposure function '||'manifest'),'UTF8'),'sha256'),'hex')<>p->>'source' THEN RETURN false;END IF;
  IF f.prokind<>'f' OR f.proretset OR f.proleakproof OR f.provariadic<>0 OR f.pronargdefaults<>0 OR f.proallargtypes IS NOT NULL OR f.proargmodes IS NOT NULL
  OR f.prorettype<>CASE f.proname WHEN 'fingerprint' THEN 'text'::regtype WHEN 'page' THEN 'jsonb'::regtype WHEN 'classify' THEN 'jsonb'::regtype WHEN 'resolve_risk' THEN 'jsonb'::regtype ELSE 'boolean'::regtype END
  OR f.lanname<>CASE WHEN f.proname IN('fingerprint','caller_ready') THEN 'sql' ELSE 'plpgsql' END
  OR f.proargnames IS DISTINCT FROM CASE f.proname WHEN 'fingerprint' THEN NULL::text[] WHEN 'page' THEN ARRAY['o','w','e','a','n','q','c'] WHEN 'classify' THEN ARRAY['o','w','e','agent','c'] WHEN 'resolve_risk' THEN ARRAY['o','w','e','c'] ELSE ARRAY['c'] END THEN RETURN false;END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(COALESCE(f.proacl,acldefault('f',f.proowner))) a WHERE a.grantor<>f.proowner OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR a.grantee NOT IN(f.proowner,CASE WHEN f.proname IN('page','resolve_risk','caller_ready') THEN 'zasp_discovery_api'::regrole::oid ELSE f.proowner END)) OR NOT has_function_privilege(f.proowner,f.oid,'EXECUTE') OR(f.proname IN('page','resolve_risk','caller_ready') AND NOT has_function_privilege('zasp_discovery_api',f.oid,'EXECUTE')) THEN RETURN false;END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='zasp_agent_exposure_filter_v1' AND(n.nspowner<>'zasp_discovery_authority'::regrole OR a.grantor<>n.nspowner OR a.is_grantable OR NOT((a.grantee=n.nspowner AND a.privilege_type IN('USAGE','CREATE')) OR(a.grantee='zasp_discovery_api'::regrole AND a.privilege_type='USAGE')))) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class t WHERE t.oid='zasp_agent_exposure_filter_v1.registration'::regclass AND t.relowner='zasp_discovery_authority'::regrole AND t.relrowsecurity AND t.relforcerowsecurity AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(t.relacl,acldefault('r',t.relowner))) a WHERE a.grantee<>t.relowner OR a.grantor<>t.relowner OR a.is_grantable)) OR EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND attacl IS NOT NULL) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_policy WHERE polrelid='zasp_agent_exposure_filter_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND polname='authority' AND polcmd='*' AND polpermissive AND polroles=ARRAY['zasp_discovery_authority'::regrole::oid] AND pg_get_expr(polqual,polrelid)='true' AND pg_get_expr(polwithcheck,polrelid)='true') THEN RETURN false;END IF;

 IF NOT has_schema_privilege('zasp_discovery_api','zasp_agent_exposure_filter_v1','USAGE') OR has_schema_privilege('zasp_discovery_api','zasp_agent_exposure_filter_v1','CREATE') THEN RETURN false;END IF;
 IF(SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute WHERE attrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM ARRAY['singleton','name','checksum','parent79','parent80','temporal','audit','identity','fingerprint'] THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute a LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE a.attrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND a.attnum>0 AND NOT a.attisdropped AND(NOT a.attnotnull OR a.attidentity<>'' OR a.attgenerated<>'' OR a.attacl IS NOT NULL OR a.atttypid<>CASE WHEN a.attnum=1 THEN 'boolean'::regtype ELSE 'text'::regtype END OR(a.attnum=1 AND pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM 'true') OR(a.attnum>1 AND d.oid IS NOT NULL))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype<>'n')<>3 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated) OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype='c' AND pg_get_expr(conbin,conrelid)='singleton' AND convalidated) OR EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype='n' AND(cardinality(conkey) IS DISTINCT FROM 1 OR NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=conrelid AND a.attnum=conkey[1] AND a.attnum>0 AND NOT a.attisdropped AND a.attnotnull))) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype='c')<>2 OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND contype='c' AND convalidated AND pg_get_expr(conbin,conrelid)=$checksum_expr$(checksum ~ '^[a-f0-9]{64}$'::text)$checksum_expr$) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='zasp_agent_exposure_filter_v1' AND nspowner='zasp_discovery_authority'::regrole) THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_index WHERE indrelid='zasp_agent_exposure_filter_v1.registration'::regclass)<>1 OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND indisprimary AND indisunique AND indisvalid AND indisready AND indkey::text='1') THEN RETURN false;END IF;
 IF(SELECT count(*) FROM pg_trigger WHERE tgrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND NOT tgisinternal)<>1 OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='zasp_agent_exposure_filter_v1.registration'::regclass AND NOT tgisinternal AND tgname='immutable' AND tgenabled='O' AND tgtype=58 AND tgnargs=0 AND tgfoid='zasp_temporal67.immutable()'::regprocedure) THEN RETURN false;END IF;
 RETURN r.fingerprint=zasp_agent_exposure_filter_v1.fingerprint();
EXCEPTION WHEN OTHERS THEN RETURN false;END
$$;
CREATE FUNCTION zasp_agent_exposure_filter_v1.caller_ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_agent_exposure_filter_v1.catalog_ready(c) AND public.zasp_discovery_principal_ready('zasp_discovery_api')
$$;
-- Private classification consumes only the currently fenced agent-owned
-- representation. It never returns raw policy rules or receives caller predicates.
CREATE FUNCTION zasp_agent_exposure_filter_v1.classify(o text,w text,e text,agent text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF c IS DISTINCT FROM '-- exposure filter checksum' OR o IS NULL OR w IS NULL OR e IS NULL OR agent IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR NOT public.zasp_valid_product_id(agent) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid exposure classification';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAgents'],'view');
 IF NOT COALESCE(zasp_authorization80.allowed(o,w,e,'agent',agent),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='exposure agent target refused';END IF;
 WITH fresh_entities AS NOT MATERIALIZED (
  SELECT v.*,ob.source_kind fact_kind,ob.stable_fields fact_stable,ob.attributes fact_attributes,ob.evidence_id fact_evidence
  FROM public.zasp_inventory_entities v
  JOIN public.zasp_inventory_source_observations ob ON(ob.organization_id,ob.workspace_id,ob.environment_id,ob.entity_id,ob.integration_id,ob.provider,ob.source,ob.source_native_id,ob.snapshot_id,ob.generation,ob.evidence_id,ob.identity_rule_version,ob.source_projection_version,ob.source_state)=(v.organization_id,v.workspace_id,v.environment_id,v.id,v.winning_integration_id,v.winning_provider,v.winning_source,v.winning_source_native_id,v.winning_snapshot_id,v.winning_generation,v.winning_evidence_id,v.winning_identity_rule,v.winning_source_projection,'present')
  JOIN public.zasp_discovery_snapshots snap ON(snap.organization_id,snap.workspace_id,snap.environment_id,snap.integration_id,snap.source,snap.id,snap.generation,snap.state,snap.complete,snap.is_last_good)=(ob.organization_id,ob.workspace_id,ob.environment_id,ob.integration_id,ob.source,ob.snapshot_id,ob.generation,'complete',true,true)
  JOIN public.zasp_inventory_evidence proof ON(proof.organization_id,proof.workspace_id,proof.environment_id,proof.id,proof.integration_id,proof.snapshot_id,proof.entity_id,proof.source,proof.generation)=(ob.organization_id,ob.workspace_id,ob.environment_id,ob.evidence_id,ob.integration_id,ob.snapshot_id,ob.entity_id,ob.source,ob.generation)
  WHERE(v.organization_id,v.workspace_id,v.environment_id,v.state)=(o,w,e,'active')
  AND v.observed_at<=statement_timestamp() AND v.fresh_until>statement_timestamp() AND ob.observed_at<=statement_timestamp() AND ob.fresh_until>statement_timestamp()
  AND v.stable_fields=ob.stable_fields AND v.winning_attributes=ob.attributes
 ),fresh_relationships AS NOT MATERIALIZED (
  SELECT rel.*,ob.evidence_id relation_evidence
  FROM public.zasp_inventory_relationships rel
  JOIN public.zasp_discovery_snapshots snap ON(snap.organization_id,snap.workspace_id,snap.environment_id,snap.integration_id,snap.source,snap.id,snap.state,snap.complete,snap.is_last_good)=(rel.organization_id,rel.workspace_id,rel.environment_id,rel.integration_id,rel.source,rel.snapshot_id,'complete',true,true)
  JOIN public.zasp_inventory_source_observations ob ON(ob.organization_id,ob.workspace_id,ob.environment_id,ob.integration_id,ob.source,ob.snapshot_id,ob.generation,ob.entity_id,ob.source_state)=(snap.organization_id,snap.workspace_id,snap.environment_id,snap.integration_id,snap.source,snap.id,snap.generation,rel.from_entity_id,'present')
  JOIN public.zasp_inventory_evidence proof ON(proof.organization_id,proof.workspace_id,proof.environment_id,proof.id,proof.integration_id,proof.snapshot_id,proof.entity_id,proof.source,proof.generation)=(ob.organization_id,ob.workspace_id,ob.environment_id,ob.evidence_id,ob.integration_id,ob.snapshot_id,ob.entity_id,ob.source,ob.generation)
  WHERE(rel.organization_id,rel.workspace_id,rel.environment_id,rel.state)=(o,w,e,'present') AND ob.observed_at<=statement_timestamp() AND ob.fresh_until>statement_timestamp()
 ),subject AS MATERIALIZED (
  SELECT * FROM fresh_entities WHERE id=agent AND product_kind='agent'
 ),paths AS MATERIALIZED (
  SELECT role.fact_attributes rules,role.fact_kind role_kind,role.fact_stable role_stable,binding.fact_kind binding_kind,binding.fact_stable binding_stable,
   subject.fact_stable->>'cluster' cluster,
   ARRAY[subject.fact_evidence,identity.fact_evidence,binding.fact_evidence,role.fact_evidence,uses.relation_evidence,assigned.relation_evidence,binds.relation_evidence] proof_ids
  FROM subject
  JOIN fresh_relationships uses ON uses.from_entity_id=subject.id AND uses.kind='uses_identity'
  JOIN fresh_entities identity ON identity.id=uses.to_entity_id AND identity.product_kind='identity' AND identity.fact_kind='kubernetes_service_account'
  JOIN fresh_relationships assigned ON assigned.from_entity_id=identity.id AND assigned.kind='assigned_to'
  JOIN fresh_entities binding ON binding.id=assigned.to_entity_id AND binding.fact_kind IN('kubernetes_role_binding','kubernetes_cluster_role_binding')
  JOIN fresh_relationships binds ON binds.from_entity_id=binding.id AND binds.kind='binds'
  JOIN fresh_entities role ON role.id=binds.to_entity_id AND role.fact_kind IN('kubernetes_role','kubernetes_cluster_role')
  WHERE subject.winning_provider='kubernetes' AND identity.winning_provider='kubernetes' AND binding.winning_provider='kubernetes' AND role.winning_provider='kubernetes'
  -- Edge provenance follows the entity whose source describes that edge.
  -- In particular a separately sourced SA reference is valid, while a losing
  -- agent or obsolete binding observation cannot contribute old privileges.
  AND(uses.integration_id,uses.source,uses.snapshot_id,uses.relation_evidence)=(subject.winning_integration_id,subject.winning_source,subject.winning_snapshot_id,subject.fact_evidence)
  AND subject.fact_stable->>'service_account'=identity.fact_stable->>'name' AND subject.fact_stable->>'namespace'=identity.fact_stable->>'namespace'
  AND(assigned.integration_id,assigned.source,assigned.snapshot_id)=(binding.winning_integration_id,binding.winning_source,binding.winning_snapshot_id)
  AND(binds.integration_id,binds.source,binds.snapshot_id,binds.relation_evidence)=(binding.winning_integration_id,binding.winning_source,binding.winning_snapshot_id,binding.fact_evidence)
  AND binding.fact_stable->>'role'=(CASE role.fact_kind WHEN 'kubernetes_role' THEN 'Role/' ELSE 'ClusterRole/' END)||(role.fact_stable->>'name')
  AND subject.fact_stable->>'cluster'<>'' AND identity.fact_stable->>'cluster'=subject.fact_stable->>'cluster' AND binding.fact_stable->>'cluster'=subject.fact_stable->>'cluster' AND role.fact_stable->>'cluster'=subject.fact_stable->>'cluster'
  AND((binding.fact_kind='kubernetes_role_binding' AND binding.fact_stable->>'scope'='namespace' AND binding.fact_stable->>'namespace'<>'' AND(role.fact_kind='kubernetes_cluster_role' OR role.fact_stable->>'namespace'=binding.fact_stable->>'namespace')) OR(binding.fact_kind='kubernetes_cluster_role_binding' AND binding.fact_stable->>'scope'='cluster' AND role.fact_kind='kubernetes_cluster_role'))
  AND jsonb_typeof(role.fact_attributes)='object' AND role.fact_attributes-ARRAY['namespaced','rules']='{}'::jsonb AND role.fact_attributes->'namespaced'=to_jsonb(role.fact_kind='kubernetes_role')
  AND jsonb_typeof(role.fact_attributes->'rules')='array' AND jsonb_array_length(CASE WHEN jsonb_typeof(role.fact_attributes->'rules')='array' THEN role.fact_attributes->'rules' ELSE '[]'::jsonb END)<=64
 ),scoped_rules AS MATERIALIZED (
  SELECT paths.*,ns.fact_stable->>'namespace' target_namespace,ns.fact_evidence namespace_evidence,rule
  FROM paths JOIN fresh_entities ns ON ns.fact_kind='kubernetes_namespace' AND ns.fact_stable->>'cluster'=paths.cluster AND ns.fact_stable->>'namespace'<>''
   AND(paths.binding_kind='kubernetes_cluster_role_binding' OR ns.fact_stable->>'namespace'=paths.binding_stable->>'namespace')
  CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(paths.rules->'rules')='array' THEN paths.rules->'rules' ELSE '[]'::jsonb END) rule
  WHERE jsonb_typeof(rule)='object' AND rule ?& ARRAY['api_groups','resources','verbs','resource_names','non_resource_urls'] AND rule-ARRAY['api_groups','resources','verbs','resource_names','non_resource_urls']='{}'::jsonb
  AND jsonb_typeof(rule->'api_groups')='array' AND jsonb_typeof(rule->'resources')='array' AND jsonb_typeof(rule->'verbs')='array' AND jsonb_typeof(rule->'resource_names')='array' AND jsonb_typeof(rule->'non_resource_urls')='array'
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(rule) field WHERE jsonb_array_length(CASE WHEN jsonb_typeof(field.value)='array' THEN field.value ELSE '[]'::jsonb END)>32)
  AND NOT EXISTS(SELECT 1 FROM jsonb_each(rule) field CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(field.value)='array' THEN field.value ELSE '[]'::jsonb END) element WHERE jsonb_typeof(element)<>'string')
 ),permissions AS MATERIALIZED (
  SELECT matched.family,matched.dimension,scoped_rules.proof_ids||ARRAY[namespace_evidence] proof_ids
  FROM scoped_rules CROSS JOIN LATERAL (VALUES
   ('kubernetes-pod-exec-create','code',(rule->'api_groups' ?| ARRAY['','*']) AND(rule->'resources' ?| ARRAY['pods/exec','*']) AND(rule->'verbs' ?| ARRAY['create','*']) AND rule->'resource_names'='[]'::jsonb),
   ('kubernetes-pod-create','code',(rule->'api_groups' ?| ARRAY['','*']) AND(rule->'resources' ?| ARRAY['pods','*']) AND(rule->'verbs' ?| ARRAY['create','*']) AND rule->'resource_names'='[]'::jsonb),
   ('kubernetes-job-create','code',(rule->'api_groups' ?| ARRAY['batch','*']) AND(rule->'resources' ?| ARRAY['jobs','cronjobs','*']) AND(rule->'verbs' ?| ARRAY['create','*']) AND rule->'resource_names'='[]'::jsonb),
   ('production-workload-write','impact',EXISTS(SELECT 1 FROM public.zasp_environments env WHERE(env.organization_id,env.workspace_id,env.id,env.environment_class)=(o,w,e,'production')) AND(
    ((rule->'verbs' ?| ARRAY['create','*']) AND rule->'resource_names'='[]'::jsonb AND(
      (rule->'api_groups' ?| ARRAY['','*']) AND(rule->'resources' ?| ARRAY['pods','*']) OR
      (rule->'api_groups' ?| ARRAY['apps','*']) AND(rule->'resources' ?| ARRAY['deployments','statefulsets','daemonsets','*']) OR
      (rule->'api_groups' ?| ARRAY['batch','*']) AND(rule->'resources' ?| ARRAY['jobs','cronjobs','*']))) OR
    ((rule->'verbs' ?| ARRAY['update','patch','delete','*']) AND EXISTS(
     SELECT 1 FROM fresh_entities workload CROSS JOIN LATERAL (VALUES
      ('Pod','','pods'),('Deployment','apps','deployments'),('StatefulSet','apps','statefulsets'),('DaemonSet','apps','daemonsets'),('Job','batch','jobs'),('CronJob','batch','cronjobs')
     ) target(kind,api_group,resource)
     WHERE workload.fact_kind IN('kubernetes_agent','kubernetes_workload','kubernetes_resource') AND workload.fact_stable->>'cluster'=cluster AND workload.fact_stable->>'namespace'=target_namespace AND workload.fact_stable->>'resource_kind'=target.kind AND workload.fact_stable->>'api_group'=CASE WHEN target.api_group='' THEN 'core' ELSE target.api_group END
     AND(rule->'api_groups' ?| ARRAY[target.api_group,'*']) AND(rule->'resources' ?| ARRAY[target.resource,'*']) AND(rule->'resource_names'='[]'::jsonb OR rule->'resource_names' ? (workload.fact_stable->>'name'))
    )))
   )
  ) matched(family,dimension,positive) WHERE matched.positive
 ),posture AS MATERIALIZED (
  SELECT matched.family,matched.dimension,ARRAY[subject.fact_evidence] proof_ids FROM subject CROSS JOIN LATERAL(VALUES
   ('observed-shell-command','shell',subject.fact_attributes->'posture'->'shell_execution'='true'::jsonb),
   ('sensitive-data-reach','impact',subject.fact_attributes->'posture'->'sensitive_data_reach'='true'::jsonb),
   ('production-secret-reach','impact',subject.fact_attributes->'posture'->'production_secret_reach'='true'::jsonb),
   ('production-write','impact',subject.fact_attributes->'posture'->'production_write'='true'::jsonb),
   ('destructive-tool-capability','impact',subject.fact_attributes->'posture'->'destructive_tool'='true'::jsonb)
  ) matched(family,dimension,positive) WHERE matched.positive
 ),facts AS MATERIALIZED(SELECT * FROM permissions UNION ALL SELECT * FROM posture)
 SELECT jsonb_build_object('definition','agent-exposure-v1','shell',EXISTS(SELECT 1 FROM facts WHERE dimension='shell'),'code',EXISTS(SELECT 1 FROM facts WHERE dimension='code'),'impact',EXISTS(SELECT 1 FROM facts WHERE dimension='impact'),'families',COALESCE((SELECT jsonb_agg(family ORDER BY family) FROM(SELECT DISTINCT family FROM facts) f),'[]'::jsonb),'evidence_ids',COALESCE((SELECT jsonb_agg(id ORDER BY id) FROM(SELECT DISTINCT unnest(proof_ids) id FROM facts) p),'[]'::jsonb)) INTO result;
 RETURN result;
END
$$;
CREATE FUNCTION zasp_agent_exposure_filter_v1.resolve_risk(o text,w text,e text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;BEGIN
 IF NOT zasp_agent_exposure_filter_v1.caller_ready(c) OR NOT zasp_authorization79.reader() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='exposure resolver unavailable';END IF;
 IF o IS NULL OR w IS NULL OR e IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid exposure resolver scope';END IF;
 -- Copy the released canonical finding visibility predicate, not a new
 -- severity/status policy or browser-readable finding representation.
 SELECT COALESCE(jsonb_agg(jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'kind','finding','id',f.id,'source_id',f.id,'version',f.version) ORDER BY f.id),'[]'::jsonb) INTO result
 FROM(SELECT finding.id,finding.version FROM public.zasp_risk_findings finding
  WHERE(finding.organization_id,finding.workspace_id,finding.environment_id)=(o,w,e) AND finding.status IN('open','under_review','accepted')
  AND COALESCE(finding.source<>'prowler' OR finding.agent_id IS NOT NULL OR finding.path_id IS NOT NULL OR finding.compliance_context IS NOT NULL,false)
  AND EXISTS(SELECT 1 FROM public.zasp_inventory_entities agent WHERE(agent.organization_id,agent.workspace_id,agent.environment_id,agent.id,agent.product_kind,agent.state)=(o,w,e,finding.agent_id,'agent','active'))
  ORDER BY finding.id LIMIT 10001) f;
 IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='exposure candidates exceed bound';END IF;
 RETURN result;
END
$$;
CREATE FUNCTION zasp_agent_exposure_filter_v1.page(o text,w text,e text,a text,n integer,q jsonb,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;current_targets jsonb;signed_targets jsonb;BEGIN
 IF NOT zasp_agent_exposure_filter_v1.caller_ready(c) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='agent exposure profile unavailable';END IF;
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listAgents'],'view');
 IF o IS NULL OR w IS NULL OR e IS NULL OR n IS NULL OR NOT public.zasp_valid_product_id(o) OR NOT public.zasp_valid_product_id(w) OR NOT public.zasp_valid_product_id(e) OR a IS NOT NULL AND NOT public.zasp_valid_product_id(a) OR n NOT BETWEEN 1 AND 100 OR q IS NULL OR jsonb_typeof(q)<>'object' OR octet_length(q::text)>4096 OR q-ARRAY['owner','risk','execution','impact']<>'{}'::jsonb OR EXISTS(SELECT 1 FROM jsonb_each(q) p WHERE jsonb_typeof(p.value)<>'string') OR q ? 'owner' AND(char_length(q->>'owner')>128 OR octet_length(q->>'owner')>512 OR q->>'owner'~'[\x01-\x1F\x7F]') OR q ? 'risk' AND q->>'risk' NOT IN('critical','high','medium','low','unknown') OR q ? 'execution' AND q->>'execution' NOT IN('shell','code','shell_or_code','unknown') OR q ? 'impact' AND q->>'impact' NOT IN('high','unknown') OR public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid agent exposure page';END IF;
 -- Permission revision is not classification-source revision. Reconstruct the
 -- COMPLETE current reference union including denied finding refs, then derive
 -- only live classification. Never reuse a pre-Check severity or source flag.
 current_targets:=zasp_authorization80.resolve(o,w,e,'agent',NULL);
 IF q ? 'risk' THEN current_targets:=current_targets||zasp_agent_exposure_filter_v1.resolve_risk(o,w,e,c);END IF;
 IF jsonb_array_length(current_targets)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='exposure candidates exceed bound';END IF;
 SELECT COALESCE(jsonb_agg(x ORDER BY x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'kind',x->>'id',x->>'source_id',x->>'version'),'[]'::jsonb) INTO current_targets FROM jsonb_array_elements(current_targets) x;
 SELECT COALESCE(jsonb_agg(x ORDER BY x->>'organization_id',x->>'workspace_id',x->>'environment_id',x->>'kind',x->>'id',x->>'source_id',x->>'version'),'[]'::jsonb) INTO signed_targets FROM jsonb_array_elements(zasp_authorization80.context()->'targets') x;
 IF current_targets IS DISTINCT FROM signed_targets THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='exposure candidates changed';END IF;
 WITH authorized_agents AS MATERIALIZED(
  SELECT id FROM public.zasp_inventory_entities v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.product_kind,v.state)=(o,w,e,'agent','active') AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,'agent',id)
  AND(NOT q ? 'owner' OR(public.zasp_inventory_annotation_value(o,w,e,id)->>'owner') COLLATE "C"=(q->>'owner') COLLATE "C")
 ),classified AS MATERIALIZED(
  SELECT agent.id,zasp_agent_exposure_filter_v1.classify(o,w,e,agent.id,c) facts,COALESCE((SELECT CASE max(CASE finding.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END) WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' END FROM public.zasp_risk_findings finding WHERE q ? 'risk' AND(finding.organization_id,finding.workspace_id,finding.environment_id,finding.agent_id)=(o,w,e,agent.id) AND finding.status IN('open','under_review','accepted') AND COALESCE(finding.source<>'prowler' OR finding.agent_id IS NOT NULL OR finding.path_id IS NOT NULL OR finding.compliance_context IS NOT NULL,false) AND zasp_authorization80.allowed(o,w,e,'finding',finding.id)),'unknown') recorded_risk
  FROM authorized_agents agent
 ),candidates AS MATERIALIZED(
  SELECT id FROM classified WHERE(NOT q ? 'risk' OR recorded_risk=q->>'risk')
  AND(NOT q ? 'execution' OR CASE q->>'execution' WHEN 'shell' THEN facts->'shell'='true'::jsonb WHEN 'code' THEN facts->'code'='true'::jsonb WHEN 'shell_or_code' THEN facts->'shell'='true'::jsonb OR facts->'code'='true'::jsonb WHEN 'unknown' THEN facts->'shell'='false'::jsonb AND facts->'code'='false'::jsonb ELSE false END)
  AND(NOT q ? 'impact' OR CASE q->>'impact' WHEN 'high' THEN facts->'impact'='true'::jsonb WHEN 'unknown' THEN facts->'impact'='false'::jsonb ELSE false END)
  ORDER BY id LIMIT n+1
 ),visible AS(SELECT id FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(public.zasp_inventory_detail(o,w,e,id,'agent')->'summary' ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result;
 RETURN result;
END
$$;
DO $owners$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_agent_exposure_filter_v1'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_discovery_api',f);END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_agent_exposure_filter_v1 TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_agent_exposure_filter_v1.page(text,text,text,text,integer,jsonb,text),zasp_agent_exposure_filter_v1.resolve_risk(text,text,text,text),zasp_agent_exposure_filter_v1.caller_ready(text) TO zasp_discovery_api;
