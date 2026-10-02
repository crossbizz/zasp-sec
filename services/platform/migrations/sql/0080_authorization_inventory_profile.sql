-- Optional inventory consumers. Existing canonical61/79/80 objects stay exact.
CREATE SCHEMA zasp_authorization80_inventory AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_inventory FROM PUBLIC;
CREATE TABLE zasp_authorization80_inventory.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),catalog jsonb NOT NULL);
ALTER TABLE zasp_authorization80_inventory.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_inventory.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80_inventory.registration FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80_inventory.registration TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE FUNCTION zasp_authorization80_inventory.immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory catalog immutable';END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_inventory.registration FOR EACH STATEMENT EXECUTE FUNCTION zasp_authorization80_inventory.immutable();
CREATE FUNCTION zasp_authorization80_inventory.catalog() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
-- inventory catalog query
$catalog$;
CREATE FUNCTION zasp_authorization80_inventory.ready(c text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ready$
 SELECT COALESCE(c='-- inventory profile checksum'
 AND(SELECT count(*)=1 FROM zasp_authorization80_inventory.registration)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_inventory.registration WHERE checksum=c AND catalog=zasp_authorization80_inventory.catalog())
 AND zasp_authorization80.ready('-- inventory80 checksum')
 AND public.zasp_sa_multistep_readiness('-- inventory61 checksum','-- inventory61 fingerprint'),false)
$ready$;
CREATE FUNCTION zasp_authorization80_inventory.api_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $api_ready$
 SELECT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api')
 AND NOT pg_has_role(session_user,'zasp_discovery_api','MEMBER')
 AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN('zasp_inventory_detail','zasp_inventory_update_agent','zasp_inventory_agent_capabilities_page','zasp_inventory_agent_relationships_page','zasp_inventory_agent_sessions_page') AND has_function_privilege(session_user,oid,'EXECUTE')),false)
$api_ready$;
CREATE FUNCTION zasp_authorization80_inventory.admit(o text,w text,e text,k text,i text,op text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.context();
 IF NOT COALESCE(zasp_authorization80_inventory.ready(c) AND zasp_authorization80_inventory.api_ready()
 AND(p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'operation_id',p#>>'{path_parameters,id}')=(o,w,e,op,i)
 AND zasp_authorization80.allowed(o,w,e,k,i),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory request rejected';END IF;
 RETURN p;
END $$;
CREATE FUNCTION zasp_authorization80_inventory.detail(o text,w text,e text,i text,k text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE op text;
BEGIN
 op:=CASE k WHEN 'agent' THEN 'getAgent' WHEN 'tool' THEN 'getTool' WHEN 'identity' THEN 'getIdentity' WHEN 'runtime' THEN 'getRuntime' WHEN 'asset' THEN 'getAsset' END;
 IF op IS NULL THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inventory kind rejected';END IF;
 PERFORM zasp_authorization80_inventory.admit(o,w,e,k,i,op,c);
 RETURN public.zasp_inventory_detail(o,w,e,i,k);
END $$;
CREATE FUNCTION zasp_authorization80_inventory.update_agent(o text,w text,e text,p text,a text,key text,v bigint,own text,team text,tags jsonb,audit text,correlation text,c text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;
BEGIN
 proof:=zasp_authorization80_inventory.admit(o,w,e,'agent',a,'updateAgent',c);
 IF proof->>'principal_id' IS DISTINCT FROM p THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory actor rejected';END IF;
 RETURN public.zasp_inventory_update_agent(o,w,e,p,a,key,v,own,team,tags,audit,correlation);
END $$;
-- inventory retained capability page
-- inventory retained relationship page
CREATE FUNCTION zasp_authorization80_inventory.capabilities_page(o text,w text,e text,a text,after_value text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80_inventory.admit(o,w,e,'agent',a,'getAgentCapabilities',c);
 RETURN zasp_authorization80_inventory._capabilities_page(o,w,e,a,after_value,n);
END $$;
CREATE FUNCTION zasp_authorization80_inventory.relationships_page(o text,w text,e text,a text,after_value text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80_inventory.admit(o,w,e,'agent',a,'getAgentRelationships',c);
 RETURN zasp_authorization80_inventory._relationships_page(o,w,e,a,after_value,n);
END $$;
CREATE FUNCTION zasp_authorization80_inventory.sessions_page(o text,w text,e text,a text,after_value text,n integer,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80_inventory.admit(o,w,e,'agent',a,'listAgentSessions',c);
 IF public.zasp_inventory_scope_state(o,w,e)->>'phase' IS DISTINCT FROM 'cutover' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inventory scope cutover required';END IF;
 IF NOT COALESCE(n BETWEEN 1 AND 100 AND(after_value IS NULL OR public.zasp_valid_product_id(after_value)),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inventory session page rejected';END IF;
 WITH candidates AS(SELECT s.id,(SELECT min(x.event_time) FROM public.zasp_runtime_session_events x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.session_id)=(o,w,e,a,s.id) AND x.confidence IN('exact','strong')) started_at
 FROM public.zasp_runtime_session_summaries s WHERE(s.organization_id,s.workspace_id,s.environment_id)=(o,w,e)
 AND EXISTS(SELECT 1 FROM public.zasp_runtime_session_events x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.session_id)=(o,w,e,a,s.id) AND x.confidence IN('exact','strong'))
 AND zasp_authorization80.allowed(o,w,e,'session',s.id) AND(after_value IS NULL OR s.id>after_value) ORDER BY s.id LIMIT n+1),visible AS(SELECT * FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE(jsonb_agg(jsonb_build_object('id',id,'agent_id',a,'started_at',rtrim(rtrim(to_char(started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z') ORDER BY id),'[]'::jsonb),'next_key',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END) INTO result FROM visible;
 RETURN result;
END $$;
CREATE FUNCTION zasp_authorization80_inventory.resolve(o text,w text,e text,op text,a text,c text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;parent jsonb;candidates jsonb;
BEGIN
 IF NOT(zasp_authorization80_inventory.ready(c) AND zasp_authorization80_inventory.api_ready()) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inventory resolver unavailable';END IF;
 IF op NOT IN('getAgentCapabilities','getAgentRelationships','listAgentSessions') OR NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(a),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inventory resolver rejected';END IF;
 parent:=zasp_authorization80.resolve(o,w,e,'agent',a);
 IF jsonb_array_length(parent)<>1 THEN RETURN '[]'::jsonb;END IF;
 WITH secondary(k,i) AS(
 SELECT entity.product_kind,edge.target_id FROM public.zasp_inventory_agent_capability_edges(o,w,e,a) edge JOIN public.zasp_inventory_entities entity ON(entity.organization_id,entity.workspace_id,entity.environment_id,entity.id,entity.state)=(o,w,e,edge.target_id,'active') WHERE op='getAgentCapabilities'
 UNION
 SELECT entity.product_kind,entity.id FROM public.zasp_inventory_relationships r JOIN public.zasp_inventory_entities entity ON(entity.organization_id,entity.workspace_id,entity.environment_id,entity.state)=(o,w,e,'active') AND entity.id IN(r.from_entity_id,r.to_entity_id) WHERE op='getAgentRelationships' AND(r.organization_id,r.workspace_id,r.environment_id,r.state)=(o,w,e,'present') AND a IN(r.from_entity_id,r.to_entity_id)
 UNION
 SELECT 'session',s.id FROM public.zasp_runtime_session_summaries s WHERE op='listAgentSessions' AND(s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND EXISTS(SELECT 1 FROM public.zasp_runtime_session_events x WHERE(x.organization_id,x.workspace_id,x.environment_id,x.agent_id,x.session_id)=(o,w,e,a,s.id) AND x.confidence IN('exact','strong'))
 ),bounded AS(SELECT DISTINCT k,i FROM secondary WHERE(k,i) IS DISTINCT FROM('agent',a) ORDER BY k,i LIMIT 10001)
 SELECT COALESCE(jsonb_agg(jsonb_build_object('kind',k,'id',i) ORDER BY k,i),'[]'::jsonb) INTO candidates FROM bounded;
 IF jsonb_array_length(candidates)+jsonb_array_length(parent)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='inventory authorization candidates exceed bound';END IF;
 -- Resolve actual source identities and versions through the registered
 -- authorization adapter. Inventory version and annotation_version differ.
 SELECT COALESCE(jsonb_agg(target ORDER BY candidate->>'kind',candidate->>'id'),'[]'::jsonb) INTO result
 FROM jsonb_array_elements(candidates) candidate
 CROSS JOIN LATERAL jsonb_array_elements(zasp_authorization80.resolve(o,w,e,candidate->>'kind',candidate->>'id')) target;
 result:=parent||result;
 IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='inventory authorization candidates exceed bound';END IF;
 RETURN result;
END $$;
DO $ownership$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_inventory'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
 END LOOP;
END $ownership$;
GRANT USAGE ON SCHEMA zasp_authorization80_inventory TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80_inventory.ready(text),zasp_authorization80_inventory.api_ready(),zasp_authorization80_inventory.detail(text,text,text,text,text,text),zasp_authorization80_inventory.update_agent(text,text,text,text,text,text,bigint,text,text,jsonb,text,text,text),zasp_authorization80_inventory.capabilities_page(text,text,text,text,text,integer,text),zasp_authorization80_inventory.relationships_page(text,text,text,text,text,integer,text),zasp_authorization80_inventory.sessions_page(text,text,text,text,text,integer,text),zasp_authorization80_inventory.resolve(text,text,text,text,text,text) TO zasp_security_agent_api;
