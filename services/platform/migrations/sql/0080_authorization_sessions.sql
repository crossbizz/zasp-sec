-- SQL80 session readers retain the verified41/44/50 representation and scope
-- validation. Only current fenced Check evidence can admit a session.
GRANT SELECT ON public.zasp_session_events TO zasp_discovery_authority;
-- Registered61 validates its private predecessor chain. Historical public
-- readiness intentionally stays closed on61; bind the original reader source
-- identities here without weakening or replacing those released functions.
CREATE FUNCTION zasp_authorization80.session_source_readiness(v integer,c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(v IN(41,50)
 AND c=CASE v WHEN 41 THEN '-- authorization80 session41 checksum' WHEN 50 THEN '-- authorization80 session50 checksum' END
 AND f=CASE v WHEN 41 THEN '-- authorization80 session41 fingerprint' WHEN 50 THEN '-- authorization80 session50 fingerprint' END
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=v AND checksum=c AND name=CASE v WHEN 41 THEN 'production_runtime_session_reads' WHEN 50 THEN 'production_runtime_sandbox_binding' END)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key=CASE v WHEN 41 THEN 'production_runtime_session_reads_fingerprint' WHEN 50 THEN 'production_runtime_sandbox_binding_fingerprint' END AND value=f)
 AND zasp_authorization80.ready('-- authorization80 checksum')
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid IN('public.zasp_runtime_session_events'::regclass,'public.zasp_runtime_session_summaries'::regclass)
  AND (NOT relrowsecurity OR NOT relforcerowsecurity OR relowner<>'zasp_discovery_authority'::regrole))
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_runtime_session_events','SELECT')
 AND NOT has_table_privilege('zasp_discovery_api','public.zasp_runtime_session_summaries','SELECT')
 AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid IN(
  'public.zasp_runtime_session_summary_json(public.zasp_runtime_session_summaries)'::regprocedure,
  'public.zasp_runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz)'::regprocedure,
  'public.zasp_runtime_session_get(text,text,text,text,text)'::regprocedure,
  'public.zasp_runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,
  'public.zasp_runtime_session_event_get(text,text,text,text,text,text)'::regprocedure,
  'public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)'::regprocedure,
  'public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)'::regprocedure)
  AND (proowner<>'zasp_discovery_authority'::regrole OR NOT prosecdef OR NOT COALESCE(proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',oid,'EXECUTE'))),false)
$$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.session_source_readiness(integer,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80.session_read_authorized(o text,w text,e text,p text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(p)
 AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND zasp_authorization80.session_source_readiness(41,'-- authorization80 session41 checksum','-- authorization80 session41 fingerprint')
 AND zasp_authorization80.ready('-- authorization80 checksum')
 AND (proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'principal_id')=(o,w,e,p),false)
 FROM (SELECT zasp_authorization80.context() proof) current_proof
$$;

-- Clone the installed and registered predecessor; exact replacement counts
-- make unexpected predecessor drift an installation failure, never a fallback.
DO $session_reads$
DECLARE signature text;definition text;name text;needle text;replacement text;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
 'runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz)',
 'runtime_session_get(text,text,text,text,text)',
 'runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer)',
 'runtime_session_event_get(text,text,text,text,text,text)',
 'runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)',
 'runtime_sandbox_session_event_get(text,text,text,text,text,text)'] LOOP
  name:=split_part(signature,'(',1);
  SELECT pg_get_functiondef(('public.zasp_'||signature)::regprocedure) INTO STRICT definition;
  needle:='FUNCTION public.zasp_'||name||'(';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session authorization predecessor rejected';END IF;
  definition:=replace(definition,needle,'FUNCTION zasp_authorization80.'||name||'(');
  needle:='zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value)';
  replacement:='zasp_authorization80.session_read_authorized(organization_value,workspace_value,environment_value,principal_value)';
  replacement:='('||replacement||' AND zasp_authorization80.context()->>''operation_id''='||quote_literal(CASE name WHEN 'runtime_session_page' THEN 'listSessions' WHEN 'runtime_session_get' THEN 'getSession' WHEN 'runtime_session_event_page' THEN 'listSessionEvents' WHEN 'runtime_sandbox_session_event_page' THEN 'listSessionEvents' ELSE 'getSessionEvent' END)||')';
  IF name<>'runtime_session_page' THEN
   replacement:='('||replacement||' AND zasp_authorization80.context()#>>''{path_parameters,id}''=id_value AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,''session'',id_value))';
  END IF;
  IF name IN('runtime_session_event_get','runtime_sandbox_session_event_get') THEN
   replacement:='('||replacement||' AND zasp_authorization80.context()#>>''{path_parameters,eventId}''=event_value)';
  END IF;
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session authorization admission predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
  IF name LIKE 'runtime_sandbox_session_event_%' THEN
   needle:='zasp_production_runtime_sandbox_binding_readiness(';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session authorization sandbox predecessor rejected';END IF;
   definition:=replace(definition,needle,'zasp_authorization80.session_source_readiness(50,');
  END IF;
  IF name='runtime_session_page' THEN
   needle:='AND (after_value='''' OR summary_value.id>after_value)';
   replacement:='AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,''session'',summary_value.id) '||needle;
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session authorization pagination predecessor rejected';END IF;
   definition:=replace(definition,needle,replacement);
  END IF;
  EXECUTE definition;
 END LOOP;
END
$session_reads$;

CREATE FUNCTION zasp_authorization80.product_session_page(text,text,text,text,integer,text,text,timestamptz,timestamptz) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY item->>'id'), '[]'::jsonb)) FROM (SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', '[]'::jsonb) AS item FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND ($4='' OR session_id>$4) AND ($6='' OR principal_id=$6) AND ($7='' OR $7='product-console') AND ($8::timestamptz IS NULL OR authenticated_at >= $8) AND ($9::timestamptz IS NULL OR authenticated_at <= $9) AND zasp_authorization80.context()->>'operation_id'='listSessions' AND zasp_authorization80.allowed($1,$2,$3,'product_session',session_id) ORDER BY session_id LIMIT $5) AS page
$$;

CREATE FUNCTION zasp_authorization80.product_session_get(text,text,text,text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('id', session_id, 'agent_id', 'product-console', 'principal_id', principal_id, 'workspace_id', workspace_id, 'environment_id', environment_id, 'state', CASE WHEN revoked_at IS NULL AND expires_at > now() THEN 'active' WHEN revoked_at IS NOT NULL THEN 'revoked' ELSE 'expired' END, 'authenticated_at', authenticated_at, 'expires_at', expires_at, 'version', version, 'events', '[]'::jsonb) FROM zasp_product_sessions AS session WHERE organization_id=$1 AND workspace_id=$2 AND environment_id=$3 AND session_id=$4 AND zasp_authorization80.context()->>'operation_id'='getSession' AND zasp_authorization80.context()#>>'{path_parameters,id}'=$4 AND zasp_authorization80.allowed($1,$2,$3,'product_session',session_id)
$$;

CREATE FUNCTION zasp_authorization80.product_session_event_page(text,text,text,text,timestamptz,text,integer) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT jsonb_build_object('items', COALESCE(jsonb_agg(item ORDER BY at,id), '[]'::jsonb)) FROM (SELECT id,at,jsonb_build_object('id', id, 'session_id', session_id, 'class', class, 'label', label, 'evidence_id', evidence_id, 'source', source, 'confidence', confidence, 'at', at) AS item FROM zasp_session_events WHERE organization_id=$1 AND session_id=$2 AND EXISTS (SELECT 1 FROM zasp_product_sessions WHERE organization_id=$1 AND workspace_id=$3 AND environment_id=$4 AND session_id=$2) AND zasp_authorization80.context()->>'operation_id'='listSessionEvents' AND zasp_authorization80.context()#>>'{path_parameters,id}'=$2 AND zasp_authorization80.allowed($1,$3,$4,'product_session',session_id) AND ($5::timestamptz IS NULL OR (at,id)>($5,$6)) ORDER BY at,id LIMIT $7) page
$$;

GRANT EXECUTE ON FUNCTION
 zasp_authorization80.runtime_session_page(text,text,text,text,text,integer,text,timestamptz,timestamptz),
 zasp_authorization80.runtime_session_get(text,text,text,text,text),
 zasp_authorization80.runtime_session_event_page(text,text,text,text,text,timestamptz,text,integer),
 zasp_authorization80.runtime_session_event_get(text,text,text,text,text,text),
 zasp_authorization80.runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer),
 zasp_authorization80.runtime_sandbox_session_event_get(text,text,text,text,text,text),
 zasp_authorization80.product_session_page(text,text,text,text,integer,text,text,timestamptz,timestamptz),
 zasp_authorization80.product_session_get(text,text,text,text),
 zasp_authorization80.product_session_event_page(text,text,text,text,timestamptz,text,integer)
 TO zasp_discovery_api;
