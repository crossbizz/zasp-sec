-- Checked search keeps source43/50 query validation and status representation.
-- Scope-wide status requires its own environment Check at the native boundary.
CREATE FUNCTION zasp_authorization80.session_query_authorized(o text,w text,e text,p text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listSessions'],'investigate_sessions',true,p);
 RETURN COALESCE(zasp_authorization80.session_read_authorized(o,w,e,p)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=43 AND name='production_runtime_session_query' AND checksum='-- authorization80 session43 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_runtime_session_query_fingerprint' AND value='-- authorization80 session43 fingerprint')
 AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid IN(
  'public.zasp_runtime_session_query_status(text,text,text,text)'::regprocedure,
  'public.zasp_runtime_session_query_hydrate(text,text,text,text,text[])'::regprocedure,
  'public.zasp_runtime_sandbox_query_status(text,text,text,text)'::regprocedure,
  'public.zasp_runtime_sandbox_query_hydrate(text,text,text,text,text[])'::regprocedure)
  AND(proowner<>'zasp_discovery_authority'::regrole OR NOT prosecdef OR NOT COALESCE(proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',oid,'EXECUTE'))),false);
END
$$;

DO $session_search$
DECLARE signature text;name text;definition text;needle text;replacement text;status_name text;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
 'runtime_session_query_status(text,text,text,text)',
 'runtime_session_query_hydrate(text,text,text,text,text[])',
 'runtime_sandbox_query_status(text,text,text,text)',
 'runtime_sandbox_query_hydrate(text,text,text,text,text[])'] LOOP
  name:=split_part(signature,'(',1);
  SELECT pg_get_functiondef(('public.zasp_'||signature)::regprocedure) INTO STRICT definition;
  needle:='FUNCTION public.zasp_'||name||'(';
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session search predecessor rejected';END IF;
  definition:=replace(definition,needle,'FUNCTION zasp_authorization80.'||name||'(');
  IF name LIKE '%_status' THEN
   needle:='zasp_runtime_session_read_authorized(organization_value,workspace_value,environment_value,principal_value)';
   replacement:='zasp_authorization80.session_query_authorized(organization_value,workspace_value,environment_value,principal_value)';
  ELSE
   status_name:=replace(name,'_hydrate','_status');
   needle:='status_value:=zasp_'||status_name||'(';
   replacement:='status_value:=zasp_authorization80.'||status_name||'(';
  END IF;
  IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session search admission predecessor rejected';END IF;
  definition:=replace(definition,needle,replacement);
  IF name LIKE '%_status' THEN
   needle:='IF NOT zasp_authorization80.session_query_authorized(organization_value,workspace_value,environment_value,principal_value) THEN RETURN NULL;END IF;';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session search status boundary rejected';END IF;
   definition:=replace(definition,needle,needle||E'\n IF NOT COALESCE((zasp_authorization80.context()->>''environment_view'')::boolean,false) THEN RETURN jsonb_build_object(''visibility'',''resource_only'');END IF;');
  END IF;
  IF name LIKE '%_hydrate' THEN
   needle:='AND id=ANY(ids_value)';
   replacement:='AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,''session'',id) '||needle;
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session search hydration predecessor rejected';END IF;
   definition:=replace(definition,needle,replacement);
  END IF;
  IF name LIKE 'runtime_sandbox_%' THEN
   needle:='zasp_production_runtime_sandbox_binding_readiness(';
   IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='session search sandbox predecessor rejected';END IF;
   definition:=replace(definition,needle,'zasp_authorization80.session_source_readiness(50,');
  END IF;
  EXECUTE definition;
 END LOOP;
END
$session_search$;
GRANT EXECUTE ON FUNCTION
 zasp_authorization80.runtime_session_query_status(text,text,text,text),
 zasp_authorization80.runtime_session_query_hydrate(text,text,text,text,text[]),
 zasp_authorization80.runtime_sandbox_query_status(text,text,text,text),
 zasp_authorization80.runtime_sandbox_query_hydrate(text,text,text,text,text[])
 TO zasp_discovery_api;
