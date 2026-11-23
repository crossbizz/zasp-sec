-- Append-only review receipts. Effective approval is resolved against the current
-- inventory and declaration in the same snapshot on every read.
CREATE TABLE IF NOT EXISTS public.zasp_addon_deployment_approvals (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 version_id text NOT NULL,agent_id text NOT NULL,revision bigint NOT NULL CHECK (revision>0),
 actor text NOT NULL,request_key text NOT NULL,permission_context_digest text NOT NULL CHECK(permission_context_digest ~ '^sha256:[0-9a-f]{64}$'),
 state text NOT NULL CHECK(state IN ('approved','revoked')),receipt jsonb NOT NULL,reviewed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,version_id,agent_id,revision),
 UNIQUE(organization_id,workspace_id,environment_id,actor,request_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,version_id) REFERENCES public.zasp_addon_versions,
 FOREIGN KEY(organization_id,workspace_id,environment_id,agent_id) REFERENCES public.zasp_inventory_entities(organization_id,workspace_id,environment_id,id)
);
ALTER TABLE public.zasp_addon_deployment_approvals OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_addon_deployment_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_addon_deployment_approvals FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_addon_deployment_approvals FROM PUBLIC;
DO $rls$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_addon_deployment_approvals' AND policyname='deployment_authority') THEN
  CREATE POLICY deployment_authority ON public.zasp_addon_deployment_approvals TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.deployment_value(o text,w text,e text,v text,i text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $context$
 WITH RECURSIVE binding AS (
  SELECT a.id,a.winning_attributes,ver.manifest_digest,ver.revision,ver.review_state
  FROM public.zasp_inventory_entities a JOIN public.zasp_addon_versions ver
   ON (ver.organization_id,ver.workspace_id,ver.environment_id,ver.id)=(a.organization_id,a.workspace_id,a.environment_id,v)
  WHERE (a.organization_id,a.workspace_id,a.environment_id,a.id,a.product_kind,a.state)=(o,w,e,i,'agent','active')
 ), grants(depth,from_id,to_id,kind) AS (
  SELECT 0,i,i,'agent'::text FROM binding
  UNION
  SELECT g.depth+1,r.from_entity_id,r.to_entity_id,r.kind FROM grants g JOIN public.zasp_inventory_relationships r
   ON (r.organization_id,r.workspace_id,r.environment_id,r.from_entity_id,r.state)=(o,w,e,g.to_id,'present')
  WHERE (g.depth=0 AND r.kind IN ('uses_identity','depends_on','connects_to')) OR
        (g.depth BETWEEN 1 AND 2 AND r.kind IN ('assigned_to','has_permission','binds'))
 ), permissions AS (
  SELECT coalesce(jsonb_agg(jsonb_build_array(g.from_id,g.kind,g.to_id,t.state,
   encode(sha256(convert_to(coalesce(t.winning_attributes,'{}'::jsonb)::text,'UTF8')),'hex'))
   ORDER BY g.depth,g.from_id,g.kind,g.to_id),'[]'::jsonb) AS facts,
   count(*) FILTER (WHERE g.depth=1 AND g.kind='uses_identity' AND t.state='active') AS identity_count
  FROM grants g LEFT JOIN public.zasp_inventory_entities t
   ON (t.organization_id,t.workspace_id,t.environment_id,t.id)=(o,w,e,g.to_id)
 ), purpose AS (
  SELECT p.revision,p.allowed_tool_ids FROM public.zasp_agent_purpose_versions p
  WHERE (p.organization_id,p.workspace_id,p.environment_id,p.agent_id)=(o,w,e,i) ORDER BY revision DESC LIMIT 1
 ), access AS (
  SELECT a.revision,a.settings FROM public.zasp_action_analysis_versions a
  WHERE (a.organization_id,a.workspace_id,a.environment_id,a.agent_id)=(o,w,e,i) ORDER BY revision DESC LIMIT 1
 ), current_value AS (
  SELECT 'sha256:'||encode(sha256(convert_to(jsonb_build_array('deployment.v1',o,w,e,v,i,b.manifest_digest,b.revision,p.revision,p.allowed_tool_ids,a.revision,a.settings,x.facts)::text,'UTF8')),'hex') AS digest,
   coalesce(p.revision,0) AS purpose_revision,coalesce(a.revision,0) AS access_revision,
   x.identity_count,b.review_state='approved' AS version_approved,coalesce(a.settings->'allowed_classifications','[]'::jsonb) classifications,
   coalesce(a.settings->'allowed_destinations','[]'::jsonb) destinations
  FROM binding b CROSS JOIN permissions x LEFT JOIN purpose p ON true LEFT JOIN access a ON true
 ), latest AS (
  SELECT d.* FROM public.zasp_addon_deployment_approvals d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.version_id,d.agent_id)=(o,w,e,v,i) ORDER BY revision DESC LIMIT 1
 )
 SELECT jsonb_build_object('addon_version_id',v,'agent_id',i,'permission_context_digest',c.digest,
  'state',CASE WHEN d.revision IS NULL THEN 'pending' WHEN d.state='approved' AND d.permission_context_digest<>c.digest THEN 'needs_re_review' ELSE d.state END,
  'revision',coalesce(d.revision,0),'purpose_revision',c.purpose_revision,'access_revision',c.access_revision,
  'identity_count',c.identity_count,'version_approved',c.version_approved,'classifications',c.classifications,'destinations',c.destinations)
 FROM current_value c LEFT JOIN latest d ON true
$context$;

CREATE OR REPLACE FUNCTION zasp_authorization80.deployment_get(o text,w text,e text,v text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $get$
DECLARE p jsonb;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,NULL,'getAddonDeploymentApproval','view','environment',e,false,true,false,false);
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM v OR NOT zasp_authorization80.allowed(o,w,e,'agent',i) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='deployment scope required'; END IF;
 RETURN coalesce(zasp_authorization80.deployment_value(o,w,e,v,i),'null'::jsonb);
END $get$;

CREATE OR REPLACE FUNCTION zasp_authorization80.deployment_review(o text,w text,e text,v text,i text,a text,k text,n bigint,digest_value text,decision text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $review$
DECLARE p jsonb; current_value jsonb; previous public.zasp_addon_deployment_approvals%ROWTYPE;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,a,'reviewAddonDeploymentApproval','manage_workflows','environment',e,false,true,true,true);
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM v OR NOT zasp_authorization80.allowed(o,w,e,'agent',i) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='deployment scope required'; END IF;
 IF NOT coalesce(k ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND n>=0 AND digest_value ~ '^sha256:[0-9a-f]{64}$' AND decision IN('approved','revoked'),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid deployment decision'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,a,k)::text,2));
 SELECT * INTO previous FROM public.zasp_addon_deployment_approvals r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.actor,r.request_key)=(o,w,e,a,k);
 IF FOUND THEN
  IF (previous.version_id,previous.agent_id,previous.revision,previous.permission_context_digest,previous.state)=(v,i,n+1,digest_value,decision) THEN RETURN previous.receipt; END IF;
  RETURN '"conflict"'::jsonb;
 END IF;
 PERFORM id FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,v) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 current_value:=zasp_authorization80.deployment_value(o,w,e,v,i);
 IF current_value IS NULL THEN RETURN 'null'::jsonb; END IF;
 IF (current_value->>'revision')::bigint<>n OR current_value->>'permission_context_digest'<>digest_value OR
  decision='approved' AND (current_value->>'version_approved'<>'true' OR (current_value->>'purpose_revision')::bigint=0 OR
  (current_value->>'access_revision')::bigint=0 OR (current_value->>'identity_count')::bigint=0)
 THEN RETURN '"conflict"'::jsonb; END IF;
 current_value:=current_value||jsonb_build_object('state',decision,'revision',n+1);
 INSERT INTO public.zasp_addon_deployment_approvals(organization_id,workspace_id,environment_id,version_id,agent_id,revision,actor,request_key,permission_context_digest,state,receipt)
 VALUES(o,w,e,v,i,n+1,a,k,digest_value,decision,current_value);
 PERFORM zasp_authorization80.product_settled(p); RETURN current_value;
END $review$;

DO $grants$ DECLARE f regprocedure; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.deployment_value(text,text,text,text,text)'::regprocedure,
  'zasp_authorization80.deployment_get(text,text,text,text,text)'::regprocedure,
  'zasp_authorization80.deployment_review(text,text,text,text,text,text,text,bigint,text,text)'::regprocedure] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  IF f::text NOT LIKE '%deployment_value%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f); END IF;
 END LOOP;
END $grants$;

-- Runtime linkage requires an attributed observation or a provider workload
-- record. Repository metadata alone supplies code provenance only.
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_posture(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $posture$
DECLARE entity public.zasp_inventory_entities%ROWTYPE; purpose public.zasp_agent_purpose_versions%ROWTYPE;
 observation record; categories jsonb:='[]'::jsonb; known boolean; kind text; proof text;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getAgentPostureSummary','view','agent',i,true,true,false,false);
 SELECT * INTO entity FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent');
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT * INTO purpose FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i) ORDER BY revision DESC LIMIT 1;
 SELECT ev.evidence_id,ev.event_time INTO observation FROM public.zasp_runtime_session_events ev
 WHERE (ev.organization_id,ev.workspace_id,ev.environment_id,ev.agent_id,ev.confidence)=(o,w,e,i,'exact')
 ORDER BY ev.event_time DESC,ev.event_id DESC LIMIT 1;
 IF observation.evidence_id IS NOT NULL THEN kind:='deployed_agent'; proof:='runtime_receipt';
 ELSIF entity.winning_provider='github' THEN kind:='repo_code'; proof:='repository';
 ELSIF entity.winning_attributes#>>'{discovery,platform}'=ANY(ARRAY['bedrock_agent','agentcore_runtime','kubernetes_workload','kubernetes_agent','vertex_ai_agent_engine','cloud_run_service','lambda_function','cloud_function','agentforce','copilot_studio'])
 THEN kind:='deployed_agent'; proof:='provider_workload';
 ELSE kind:='unknown'; proof:='unverified'; END IF;
 known:=coalesce(public.zasp_inventory_scope_state(o,w,e)->>'phase'='cutover',false);
 IF known THEN
  SELECT coalesce(jsonb_agg(DISTINCT c.category ORDER BY c.category),'[]'::jsonb) INTO categories FROM public.zasp_inventory_agent_capability_edges(o,w,e,i) c;
 END IF;
 RETURN jsonb_build_object('agent_id',i,'deployment_kind',kind,'deployment_evidence',proof,
  'discovery_evidence_id',entity.winning_evidence_id,'purpose_revision',coalesce(purpose.revision,0),
  'allowed_tool_ids',coalesce(purpose.allowed_tool_ids,'[]'::jsonb),'access_known',known,'granted_categories',categories,
  'last_observed_at',observation.event_time,'observed_evidence_id',observation.evidence_id);
END $posture$;
ALTER FUNCTION zasp_authorization80.agent_posture(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.agent_posture(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.agent_posture(text,text,text,text) TO zasp_discovery_api;
