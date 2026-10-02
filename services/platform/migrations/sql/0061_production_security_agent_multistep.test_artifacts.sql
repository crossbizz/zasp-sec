-- Prepared input identity is immutable and independent of invocation attempts.
-- It is not a second provider idempotency lane: the published category journal
-- still owns the one-and-only start/completion boundary.
CREATE TABLE zasp_sa_multistep_prior.test_inputs(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,test_run_id text NOT NULL,
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=16384),
 body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 65536),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id)
);
ALTER TABLE zasp_sa_multistep_prior.test_inputs OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_sa_multistep_prior.test_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_sa_multistep_prior.test_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_sa_multistep_prior.test_inputs USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON zasp_sa_multistep_prior.test_inputs FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_adapter;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_sa_multistep_prior.test_inputs FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission();

CREATE FUNCTION zasp_sa_multistep_prior.test_json(body bytea,maximum integer) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $json$
DECLARE raw json;
BEGIN
 IF octet_length(body) NOT BETWEEN 1 AND maximum THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered artifact byte bound rejected';END IF;
 BEGIN raw:=convert_from(body,'UTF8')::json;EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered artifact JSON rejected';END;
 IF EXISTS(WITH RECURSIVE nodes(value,depth) AS (
  SELECT raw,0 UNION ALL SELECT child.value,n.depth+1 FROM nodes n CROSS JOIN LATERAL (
   SELECT value FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END)
   UNION ALL SELECT value FROM json_array_elements(CASE WHEN json_typeof(n.value)='array' THEN n.value ELSE '[]'::json END)
  ) child WHERE n.depth<=24
 ) SELECT 1 FROM nodes n WHERE depth>24 OR (SELECT count(*)<>count(DISTINCT key) FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END))) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered artifact ambiguity rejected';END IF;
 RETURN raw::jsonb;
END $json$;

CREATE FUNCTION zasp_sa_multistep_prior.test_validate_input(o text,w text,e text,r text,s text,manifest jsonb,body bytea) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $input$
DECLARE doc jsonb;link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;key text;
BEGIN
 doc:=zasp_sa_multistep_prior.test_json(body,65536);
 SELECT * INTO link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id);
 key:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_test_input',r||chr(31)||s);
 IF NOT COALESCE(public.zasp_red_team_valid_input_artifact(o,w,e,manifest),false)
  OR NOT zasp_sa_multistep_prior.closed(manifest,ARRAY['reference','version_id','sha256','size_bytes']) OR octet_length(manifest::text)>16384
  OR right(manifest->>'reference',length(key)+1) IS DISTINCT FROM '/'||key
  OR manifest->>'sha256' IS DISTINCT FROM encode(digest(body,'sha256'),'hex') OR manifest->'size_bytes' IS DISTINCT FROM to_jsonb(octet_length(body))
  OR NOT zasp_sa_multistep_prior.closed(doc,ARRAY['schema_version','organization_id','workspace_id','environment_id','run_id','definition_id','definition_version','target_id','target_kind','categories','input_digest','runner_image_digest'])
  OR doc-'runner_image_digest' IS DISTINCT FROM jsonb_build_object('schema_version','red-team-runner-input-v2','organization_id',o,'workspace_id',w,'environment_id',e,'run_id',link.test_run_id,'definition_id',link.test_definition_id,'definition_version',link.test_definition_version,'target_id',link.target_id,'target_kind',link.target_kind,'categories',link.test_categories,'input_digest',encode(child.input_digest,'hex'))
  OR NOT COALESCE(jsonb_typeof(doc->'runner_image_digest')='string' AND doc->>'runner_image_digest'~'^sha256:[a-f0-9]{64}$' AND doc->>'runner_image_digest'<>'sha256:'||repeat('0',64),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered prepared input rejected';END IF;
 RETURN doc;
END $input$;
ALTER FUNCTION zasp_sa_multistep_prior.test_json(bytea,integer) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_sa_multistep_prior.test_validate_input(text,text,text,text,text,jsonb,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.test_json(bytea,integer),zasp_sa_multistep_prior.test_validate_input(text,text,text,text,text,jsonb,bytea) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_adapter;
