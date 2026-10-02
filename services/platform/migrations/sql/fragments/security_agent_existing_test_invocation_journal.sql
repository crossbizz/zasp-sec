-- Persistence core only. Future versioned admission must hold organization,
-- policy/budget and pinned target authority before calling this private core.
-- A committed started row is uncertainty, never evidence of a successful test.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(organization_value text,workspace_value text,environment_value text,target_value text,target_kind_value text,test_definition_value text,test_version_value bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog, public AS $resolve$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(zasp_red_team_principal_ready('zasp_red_team_adapter') OR zasp_red_team_principal_ready('zasp_red_team_worker'),false) OR NOT zasp_red_team_target_valid(organization_value,workspace_value,environment_value,target_value,target_kind_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='red team target resolution rejected';END IF;
 SELECT jsonb_build_object('binding',jsonb_build_object('target_id',entity_value.id,'target_kind',target_kind_value,'endpoint',entity_value.winning_attributes->'red_team'->>'endpoint','credential_reference',entity_value.winning_attributes->'red_team'->>'credential_reference','version',entity_value.version),'provenance',jsonb_build_object('integration_id',observation.integration_id,'snapshot_id',observation.snapshot_id,'evidence_id',observation.evidence_id,'source',observation.source,'generation',observation.generation),'comparison',jsonb_build_object('schema_version','red-team-target-comparison-v1','organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'test_definition_id',definition_value.definition_id,'test_definition_version',definition_value.version,'target_id',entity_value.id,'target_kind',target_kind_value,'categories',definition_value.categories,'safety_digest',encode(digest(convert_to(definition_value.safety::text,'UTF8'),'sha256'),'hex'),'endpoint_digest',encode(digest(convert_to(entity_value.winning_attributes->'red_team'->>'endpoint','UTF8'),'sha256'),'hex'),'configuration_digest',encode(digest(convert_to(entity_value.winning_attributes::text,'UTF8'),'sha256'),'hex'),'credential_binding_id',credential_value.binding_id,'credential_binding_version',credential_value.version,'credential_binding_digest',encode(credential_value.reference_digest,'hex'))) INTO STRICT result_value
 FROM zasp_inventory_entities entity_value
 JOIN zasp_red_team_definitions definition_value ON (definition_value.organization_id,definition_value.workspace_id,definition_value.environment_id,definition_value.definition_id,definition_value.version,definition_value.target_id,definition_value.target_kind,definition_value.enabled)=(organization_value,workspace_value,environment_value,test_definition_value,test_version_value,entity_value.id,target_kind_value,true)
 JOIN zasp_attack_lab_credential_bindings credential_value ON (credential_value.organization_id,credential_value.workspace_id,credential_value.environment_id,credential_value.target_id,credential_value.credential_reference,credential_value.state)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.winning_attributes->'red_team'->>'credential_reference','active') AND credential_value.valid_until>clock_timestamp()
 JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.provider,observation.source,observation.entity_id,observation.source_native_id,observation.snapshot_id,observation.generation,observation.evidence_id,observation.source_state)=(entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.winning_integration_id,entity_value.winning_provider,entity_value.winning_source,entity_value.id,entity_value.winning_source_native_id,entity_value.winning_snapshot_id,entity_value.winning_generation,entity_value.winning_evidence_id,'present')
 JOIN zasp_discovery_snapshots snapshot_value ON (snapshot_value.organization_id,snapshot_value.workspace_id,snapshot_value.environment_id,snapshot_value.integration_id,snapshot_value.source,snapshot_value.id,snapshot_value.state,snapshot_value.complete,snapshot_value.is_last_good)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.source,observation.snapshot_id,'complete',true,true)
 JOIN zasp_inventory_evidence evidence_value ON (evidence_value.organization_id,evidence_value.workspace_id,evidence_value.environment_id,evidence_value.id,evidence_value.integration_id,evidence_value.snapshot_id,evidence_value.entity_id,evidence_value.source,evidence_value.generation)=(observation.organization_id,observation.workspace_id,observation.environment_id,observation.evidence_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.source,observation.generation)
 WHERE (entity_value.organization_id,entity_value.workspace_id,entity_value.environment_id,entity_value.id,entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,target_value,'active',CASE target_kind_value WHEN 'mcp_server' THEN 'tool' ELSE 'agent' END) AND entity_value.fresh_until>clock_timestamp() AND zasp_red_team_target_binding_valid(entity_value.winning_attributes->'red_team',target_kind_value) FOR SHARE OF definition_value,entity_value,credential_value,observation,snapshot_value,evidence_value NOWAIT;
 RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='red team target unavailable';
END
$resolve$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint) FROM PUBLIC;

CREATE TABLE public.zasp_security_agent_test_invocations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 test_run_id text NOT NULL,attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 5),
 category text NOT NULL CHECK(category IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information')),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 target_resolution jsonb NOT NULL CHECK(jsonb_typeof(target_resolution)='object' AND target_resolution ?& ARRAY['binding','provenance','comparison'] AND target_resolution-ARRAY['binding','provenance','comparison']='{}'::jsonb),
 lease_digest bytea NOT NULL CHECK(octet_length(lease_digest)=32),
 state text NOT NULL CHECK(state IN('started','completed')),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,http_status integer,response_digest bytea,protected boolean,credential_version_digest bytea,
 CHECK(state='started' AND completed_at IS NULL AND http_status IS NULL AND response_digest IS NULL AND protected IS NULL AND credential_version_digest IS NULL
  OR state='completed' AND completed_at IS NOT NULL AND completed_at>=started_at AND http_status IS NOT NULL AND http_status BETWEEN 200 AND 599
   AND response_digest IS NOT NULL AND octet_length(response_digest)=32 AND credential_version_digest IS NOT NULL AND octet_length(credential_version_digest)=32 AND credential_version_digest<>decode(repeat('00',32),'hex') AND (http_status=200 AND protected IS NOT NULL OR http_status<>200 AND protected IS NULL)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,test_run_id,attempt,category),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id,category),
 FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id)
  REFERENCES public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,test_run_id)
);
ALTER TABLE public.zasp_security_agent_test_invocations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_test_invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_test_invocations FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_test_invocations_authority ON public.zasp_security_agent_test_invocations TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_security_agent_test_invocations FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_receipt(o text,w text,e text,r text,a integer,c text)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $receipt$
 SELECT jsonb_build_object('state',state,'run_id',test_run_id,'attempt',attempt,'category',category,'input_digest',encode(input_digest,'hex'),'request_digest',encode(request_digest,'hex'),
 'target_comparison',target_resolution->'comparison','target_binding',target_resolution->'binding','target_provenance',target_resolution->'provenance','http_status',http_status,'response_digest',encode(response_digest,'hex'),'credential_version_digest',encode(credential_version_digest,'hex'),'protected',protected,'completed_at',to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,attempt,category,state)=(o,w,e,r,a,c,'completed')
$receipt$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_receipt(text,text,text,text,integer,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_receipt(text,text,text,text,integer,text) FROM PUBLIC;

-- Parent admission includes current definition/plan/approval and safety checks.
-- Endpoint/provenance/comparison pinning remains for the final adapter wrapper.
-- Reuse the complete dispatch authorization contract with only the expected
-- post-dispatch states changed. Keep dispatch's original function unchanged.
DO $invocation_authorization$
DECLARE source_value text;anchor_value text;
BEGIN
 source_value:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text)'::regprocedure);
 FOREACH anchor_value IN ARRAY ARRAY['FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(', '(o,w,e,r,''planning'')', '(o,w,e,r,s,0,''authorized'')'] LOOP
  IF (length(source_value)-length(replace(source_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='invocation authorization predecessor rejected';END IF;
 END LOOP;
 source_value:=replace(source_value,'FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(','FUNCTION public.zasp_production_security_agent_existing_tests_authorize_invocation(');
 source_value:=replace(source_value,'(o,w,e,r,''planning'')','(o,w,e,r,''running'')');
 source_value:=replace(source_value,'(o,w,e,r,s,0,''authorized'')','(o,w,e,r,s,0,''executing'')');
 EXECUTE source_value;
END
$invocation_authorization$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_authorize_invocation(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_authorize_invocation(text,text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_parent(o text,w text,e text,r text)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $parent$
DECLARE link_row public.zasp_security_agent_test_links%ROWTYPE;parent_row public.zasp_security_agent_runs%ROWTYPE;
 budget_row public.zasp_security_agent_run_budgets%ROWTYPE;control_row record;control_count integer:=0;binding_value jsonb;
BEGIN
 -- Shared only by separately role-checked claim and adapter entrypoints.
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_adapter') OR public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked invocation principal rejected';END IF;
 -- Discover only the parent identity before locks. Revalidate the exact link
 -- after organization, parent, budget and step authority have been locked.
 SELECT * INTO link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation parent missing';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation organization unavailable';END IF;
 SELECT * INTO parent_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,link_row.run_id,'running') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation parent stopped';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_authorize_invocation(o,w,e,link_row.run_id,link_row.step_id);
 SELECT * INTO budget_row FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)=(o,w,e,link_row.run_id,parent_row.definition_id,parent_row.definition_version) FOR UPDATE;
 IF NOT FOUND OR budget_row.stop_reason IS NOT NULL OR budget_row.deadline_at IS NULL OR budget_row.deadline_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation budget stopped';END IF;
 PERFORM 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)=(o,w,e,link_row.run_id,link_row.step_id,link_row.action_key,link_row.input_digest,'executing') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation step stopped';END IF;
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)=(o,w,e,link_row.run_id,link_row.step_id,link_row.action_key,link_row.input_digest,'pending') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation effect stopped';END IF;
 PERFORM 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,link_row.run_id,link_row.step_id,link_row.action_key,link_row.input_digest) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation reservation missing';END IF;
 PERFORM 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,link_row.run_id,link_row.step_id,link_row.action_key,link_row.input_digest) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation parent changed';END IF;
 FOR control_row IN SELECT * FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*',link_row.action_key) ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE LOOP
  control_count:=control_count+1;
  IF NOT control_row.execution_enabled THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation execution disabled';END IF;
 END LOOP;
 binding_value:=public.zasp_production_security_agent_run_context_test_binding(o,w,e,parent_row.definition_id,parent_row.definition_version);
 IF binding_value IS DISTINCT FROM jsonb_build_object('definition_id',link_row.test_definition_id,'definition_version',link_row.test_definition_version,'target_id',link_row.target_id,'target_kind',link_row.target_kind) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation target changed';
 END IF;
 IF control_count<>3 OR budget_row.deadline_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation authority unavailable';END IF;
 RETURN budget_row.deadline_at;
END
$parent$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_parent(text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start_core(o text,w text,e text,r text,lease_value bytea,category_value text,request_digest_value bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $start$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;link_row public.zasp_security_agent_test_links%ROWTYPE;prior public.zasp_security_agent_test_invocations%ROWTYPE;parent_deadline timestamptz;target_resolution_value jsonb;
BEGIN
 IF NOT public.zasp_red_team_principal_ready('zasp_red_team_adapter') OR NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r)
  AND octet_length(lease_value)=32 AND octet_length(request_digest_value)=32
  AND category_value IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information'),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked invocation input rejected';
 END IF;
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR run_row.state<>'leased' OR run_row.lease_token IS DISTINCT FROM lease_value OR run_row.lease_expires_at<=clock_timestamp() OR run_row.cancel_requested OR run_row.attempt NOT BETWEEN 1 AND 5 THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease rejected';
 END IF;
 SELECT * INTO link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id,test_definition_id,test_definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation association rejected';END IF;
 PERFORM 1 FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,target_id,target_kind)=(o,w,e,link_row.test_definition_id,link_row.test_definition_version,link_row.target_id,link_row.target_kind) AND enabled AND categories ? category_value FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation definition rejected';END IF;
 target_resolution_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,link_row.target_id,link_row.target_kind,link_row.test_definition_id,link_row.test_definition_version);
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r) AND target_resolution IS DISTINCT FROM target_resolution_value) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation target snapshot changed';
 END IF;
 SELECT * INTO prior FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,r,category_value) FOR UPDATE;
 IF FOUND AND prior.state='completed' THEN
  IF prior.attempt<>run_row.attempt OR prior.input_digest IS DISTINCT FROM run_row.input_digest OR prior.request_digest IS DISTINCT FROM request_digest_value OR prior.lease_digest IS DISTINCT FROM digest(lease_value,'sha256') THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation replay conflict';
  END IF;
  PERFORM public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
  IF run_row.lease_expires_at<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease expired';END IF;
  RETURN public.zasp_production_security_agent_existing_tests_invocation_receipt(o,w,e,r,prior.attempt,category_value);
 END IF;
 -- A different category/attempt cannot proceed while any earlier start lacks
 -- a terminal receipt. A known receipt replay above never sends network I/O.
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,state)=(o,w,e,r,'started')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked invocation outcome unknown';
 END IF;
 INSERT INTO public.zasp_security_agent_test_invocations(organization_id,workspace_id,environment_id,test_run_id,attempt,category,input_digest,request_digest,target_resolution,lease_digest,state)
 VALUES(o,w,e,r,run_row.attempt,category_value,run_row.input_digest,request_digest_value,target_resolution_value,digest(lease_value,'sha256'),'started');
 PERFORM public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 IF run_row.lease_expires_at<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease expired';END IF;
 RETURN jsonb_build_object('state','started','attempt',run_row.attempt,'category',category_value,'input_digest',encode(run_row.input_digest,'hex'),'request_digest',encode(request_digest_value,'hex'),'target_comparison',target_resolution_value->'comparison','target_binding',target_resolution_value->'binding','target_provenance',target_resolution_value->'provenance');
END
$start$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start_core(text,text,text,text,bytea,text,bytea) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete_core(o text,w text,e text,r text,attempt_value integer,lease_value bytea,category_value text,request_digest_value bytea,status_value integer,response_digest_value bytea,protected_value boolean,credential_version_value bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $complete$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;prior public.zasp_security_agent_test_invocations%ROWTYPE;
BEGIN
 IF NOT public.zasp_red_team_principal_ready('zasp_red_team_adapter') OR NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r)
  AND attempt_value BETWEEN 1 AND 5 AND octet_length(lease_value)=32 AND octet_length(request_digest_value)=32 AND octet_length(response_digest_value)=32 AND octet_length(credential_version_value)=32 AND credential_version_value<>decode(repeat('00',32),'hex')
  AND category_value IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information')
  AND status_value BETWEEN 200 AND 599 AND (status_value=200 AND protected_value IS NOT NULL OR status_value<>200 AND protected_value IS NULL),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked invocation response rejected';
 END IF;
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation run unavailable';END IF;
 SELECT * INTO prior FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,attempt,category)=(o,w,e,r,attempt_value,category_value) FOR UPDATE;
 IF NOT FOUND OR prior.input_digest IS DISTINCT FROM run_row.input_digest OR prior.request_digest IS DISTINCT FROM request_digest_value OR prior.lease_digest IS DISTINCT FROM digest(lease_value,'sha256') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation response association rejected';
 END IF;
 IF prior.state='completed' THEN
  IF prior.http_status IS DISTINCT FROM status_value OR prior.response_digest IS DISTINCT FROM response_digest_value OR prior.protected IS DISTINCT FROM protected_value OR prior.credential_version_digest IS DISTINCT FROM credential_version_value THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation response conflict';
  END IF;
 ELSE
  -- This records a known response, including one arriving after cancellation or
  -- lease expiry. It grants no new execution authority and changes no run state.
  UPDATE public.zasp_security_agent_test_invocations SET state='completed',completed_at=clock_timestamp(),http_status=status_value,response_digest=response_digest_value,protected=protected_value,credential_version_digest=credential_version_value
  WHERE (organization_id,workspace_id,environment_id,test_run_id,attempt,category,state)=(o,w,e,r,attempt_value,category_value,'started');
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation response changed';END IF;
 END IF;
 RETURN public.zasp_production_security_agent_existing_tests_invocation_receipt(o,w,e,r,attempt_value,category_value);
END
$complete$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete_core(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea) FROM PUBLIC;

-- The registered adapter receives only versioned, release-pinned entrypoints.
-- Dispatch/worker admission remains disabled until the linked protocol ships.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start(o text,w text,e text,r text,lease_value bytea,category_value text,request_digest_value bytea,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $entry$
DECLARE result_value jsonb;parent_deadline timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_adapter'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 result_value:=public.zasp_production_security_agent_existing_tests_invocation_start_core(o,w,e,r,lease_value,category_value,request_digest_value);
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 -- Release identity checks can take time. Recheck held current authority after
 -- them, not only inside the core before those checks began.
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 PERFORM 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state='leased' AND lease_token=lease_value AND NOT cancel_requested AND attempt BETWEEN 1 AND 5 AND lease_expires_at>clock_timestamp() AND parent_deadline>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease expired';END IF;
 RETURN result_value;
END
$entry$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_start(text,text,text,text,bytea,text,bytea,text,text) TO zasp_red_team_adapter;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete(o text,w text,e text,r text,attempt_value integer,lease_value bytea,category_value text,request_digest_value bytea,status_value integer,response_digest_value bytea,protected_value boolean,credential_version_value bytea,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $entry$
DECLARE result_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_adapter'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 result_value:=public.zasp_production_security_agent_existing_tests_invocation_complete_core(o,w,e,r,attempt_value,lease_value,category_value,request_digest_value,status_value,response_digest_value,protected_value,credential_version_value);
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 RETURN result_value;
END
$entry$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_complete(text,text,text,text,integer,bytea,text,bytea,integer,bytea,boolean,bytea,text,text) TO zasp_red_team_adapter;

-- Resolution returns current authority, not permission to send. Start must still
-- commit its journal row and return this exact binding before network I/O.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_invocation_resolve(o text,w text,e text,target_value text,target_kind_value text,r text,lease_value bytea,category_value text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $entry$
DECLARE result_value jsonb;run_row public.zasp_red_team_runs%ROWTYPE;parent_deadline timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_adapter'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(target_value) AND octet_length(lease_value)=32 AND target_kind_value IN('agent_endpoint','mcp_server','coding_agent') AND category_value IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked invocation resolution rejected';END IF;
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR run_row.state<>'leased' OR run_row.lease_token IS DISTINCT FROM lease_value OR run_row.cancel_requested OR run_row.attempt NOT BETWEEN 1 AND 5 OR run_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease rejected';END IF;
 PERFORM 1 FROM public.zasp_security_agent_test_links l JOIN public.zasp_red_team_definitions d ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version,d.target_id,d.target_kind)=(l.organization_id,l.workspace_id,l.environment_id,l.test_definition_id,l.test_definition_version,l.target_id,l.target_kind)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,l.test_definition_id,l.test_definition_version,l.target_id,l.target_kind)=(o,w,e,r,run_row.definition_id,run_row.definition_version,target_value,target_kind_value) AND d.enabled AND d.categories ? category_value FOR SHARE OF l,d;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation association rejected';END IF;
 result_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,target_value,target_kind_value,run_row.definition_id,run_row.definition_version);
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r) AND target_resolution IS DISTINCT FROM result_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation target snapshot changed';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test invocation release unavailable';END IF;
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 IF run_row.lease_expires_at<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked invocation lease expired';END IF;
 RETURN result_value->'binding';
END
$entry$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_invocation_resolve(text,text,text,text,text,text,bytea,text,text,text) TO zasp_red_team_adapter;

-- This grants only a worker lease. Each target request still requires a
-- separately committed adapter reservation. Production dispatch remains off.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_worker_claim(o text,w text,e text,r text,worker_value text,lease_value bytea,lease_seconds integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;definition_row public.zasp_red_team_definitions%ROWTYPE;
 parent_deadline timestamptz;result_value jsonb;disposition_value text;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked worker principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked worker release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r)
  AND length(worker_value) BETWEEN 3 AND 128 AND worker_value~'^[a-z][a-z0-9.-]{2,127}$' AND octet_length(lease_value)=32 AND lease_seconds BETWEEN 30 AND 900,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked worker claim rejected';
 END IF;
 -- A scoped, already-terminal child needs no live execution authorization.
 -- This read-only acknowledgement never takes a child lock or grants a lease;
 -- public worker operations cannot reopen terminal runs. It remains bound to
 -- the exact persisted link and definition, even after the parent has stopped.
 IF EXISTS(SELECT 1 FROM public.zasp_red_team_runs t JOIN public.zasp_security_agent_test_links l
  ON (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,l.test_definition_id,l.test_definition_version)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.definition_version)
  WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r) AND t.state IN('complete','failed','cancelled')) THEN
  IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked worker release unavailable';END IF;
  RETURN jsonb_build_object('disposition','ack_terminal');
 END IF;
 -- Keep the same organization -> parent -> budget -> step -> test-run order
 -- as invocation. Never call the legacy claim or take the child lock first.
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker run unavailable';END IF;
 SELECT d.* INTO definition_row FROM public.zasp_red_team_definitions d JOIN public.zasp_security_agent_test_links l
 ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version,d.target_id,d.target_kind)=(l.organization_id,l.workspace_id,l.environment_id,l.test_definition_id,l.test_definition_version,l.target_id,l.target_kind)
 WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,l.test_definition_id,l.test_definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) AND d.enabled FOR SHARE OF d,l;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker definition changed';END IF;
 IF run_row.state IN('complete','failed','cancelled') THEN
  disposition_value:='ack_terminal';
 ELSIF run_row.cancel_requested THEN
  -- The eventual journal-aware canceller owns cancellation evidence/state.
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker cancellation pending';
 ELSIF run_row.state='leased' AND run_row.lease_expires_at>clock_timestamp() OR run_row.next_attempt_at>clock_timestamp() THEN
  disposition_value:='retry_later';
 ELSIF run_row.attempt>=5 OR run_row.error_code='outcome_unknown' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r)) THEN
  -- No new attempt over uncertain or previously executed work. Reconciliation
  -- distinguishes unknown outcomes from known partial/complete observations.
  disposition_value:='reconcile_required';
 ELSE
  PERFORM public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,definition_row.target_id,definition_row.target_kind,definition_row.definition_id,definition_row.version);
  parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
  UPDATE public.zasp_red_team_runs SET version=version+1,state='leased',attempt=attempt+1,error_code=NULL,worker_id=worker_value,lease_token=lease_value,
   lease_expires_at=LEAST(clock_timestamp()+make_interval(secs=>lease_seconds),parent_deadline),started_at=COALESCE(started_at,clock_timestamp()),updated_at=clock_timestamp()
  WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO run_row;
  disposition_value:='claimed';
 END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked worker release unavailable';END IF;
 result_value:=jsonb_build_object('disposition',disposition_value);
 IF disposition_value='claimed' THEN
  -- Includes waits at UPDATE and time spent verifying the complete release.
  parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
  IF run_row.lease_expires_at<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker claim expired';END IF;
  result_value:=result_value||jsonb_build_object('evidence_version','red-team-v2','run',public.zasp_red_team_run_json(run_row),'definition',public.zasp_red_team_definition_json(definition_row),'input_digest',encode(run_row.input_digest,'hex'),'lease_expires_at',run_row.lease_expires_at);
 END IF;
 RETURN result_value;
END
$claim$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_claim(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_worker_heartbeat(o text,w text,e text,r text,worker_value text,lease_value bytea,lease_seconds integer,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $heartbeat$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;definition_row public.zasp_red_team_definitions%ROWTYPE;
 parent_deadline timestamptz;prior_expiry timestamptz;new_expiry timestamptz;target_value jsonb;
 result_value jsonb:=jsonb_build_object('renewed',false,'cancel_requested',false);
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked worker principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked worker release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r)
  AND length(worker_value) BETWEEN 3 AND 128 AND worker_value~'^[a-z][a-z0-9.-]{2,127}$' AND octet_length(lease_value)=32 AND lease_seconds BETWEEN 30 AND 900,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked worker heartbeat rejected';
 END IF;
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF FOUND AND run_row.state='leased' AND run_row.worker_id=worker_value AND run_row.lease_token=lease_value AND run_row.lease_expires_at>clock_timestamp() THEN
  IF run_row.cancel_requested THEN
   -- Report the request without renewing or claiming external cancellation.
   result_value:=jsonb_build_object('renewed',false,'cancel_requested',true);
  ELSE
   SELECT d.* INTO definition_row FROM public.zasp_red_team_definitions d JOIN public.zasp_security_agent_test_links l
   ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version,d.target_id,d.target_kind)=(l.organization_id,l.workspace_id,l.environment_id,l.test_definition_id,l.test_definition_version,l.target_id,l.target_kind)
   WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id,l.test_definition_id,l.test_definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) AND d.enabled FOR SHARE OF d,l;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker definition changed';END IF;
   target_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,definition_row.target_id,definition_row.target_kind,definition_row.definition_id,definition_row.version);
   IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r) AND target_resolution IS DISTINCT FROM target_value) THEN
    RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker target snapshot changed';
   END IF;
   prior_expiry:=run_row.lease_expires_at;
   parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
   UPDATE public.zasp_red_team_runs SET lease_expires_at=LEAST(clock_timestamp()+make_interval(secs=>lease_seconds),parent_deadline),updated_at=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING lease_expires_at INTO new_expiry;
   result_value:=jsonb_build_object('renewed',true,'cancel_requested',false,'lease_expires_at',new_expiry);
  END IF;
 END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked worker release unavailable';END IF;
 IF new_expiry IS NOT NULL THEN
  parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
  -- The old lease, not the freshly written expiry, authorized this renewal.
  -- Roll the entire statement back if an UPDATE/catalog wait outlived it.
  IF prior_expiry<=clock_timestamp() OR new_expiry<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked worker heartbeat expired';
  END IF;
 END IF;
 RETURN result_value;
END
$heartbeat$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_heartbeat(text,text,text,text,text,bytea,integer,text,text) TO zasp_red_team_worker;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(o text,w text,e text,r text,worker_value text,lease_value bytea,input_digest_value bytea,verdict_value text,objective_value text,behavior_value text,error_value text,evidence_value jsonb,reference_value text,key_value text,version_value text,checksum_value bytea,size_value bigint,input_value jsonb,expected_checksum text,expected_fingerprint text,artifact_value bytea)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $finish$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;link_row public.zasp_security_agent_test_links%ROWTYPE;definition_row public.zasp_red_team_definitions%ROWTYPE;
 parent_deadline timestamptz;target_value jsonb;result_value jsonb;expected_evidence jsonb;passed integer;total integer;
 artifact_json json;artifact_doc jsonb;native_doc jsonb;records jsonb;artifact_item record;observed jsonb;expected_observation jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test completion release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r)
  AND worker_value~'^[a-z][a-z0-9.-]{2,127}$' AND octet_length(lease_value)=32 AND octet_length(input_digest_value)=32 AND input_digest_value<>decode(repeat('00',32),'hex')
  AND verdict_value IN('pass','fail','engine_error') AND (verdict_value IN('pass','fail') AND error_value IS NULL OR verdict_value='engine_error' AND error_value='outcome_unknown')
  AND objective_value IS NOT NULL AND behavior_value IS NOT NULL AND evidence_value IS NOT NULL
  AND reference_value IS NOT NULL AND key_value IS NOT NULL AND version_value IS NOT NULL
  AND octet_length(checksum_value)=32 AND checksum_value<>decode(repeat('00',32),'hex') AND size_value BETWEEN 1 AND 1048576
  AND octet_length(artifact_value)=size_value AND digest(artifact_value,'sha256')=checksum_value
  AND public.zasp_red_team_valid_input_artifact(o,w,e,input_value) AND input_value->>'reference'<>reference_value,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked completion input rejected';
 END IF;
 parent_deadline:=public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR run_row.state<>'leased' OR run_row.worker_id IS DISTINCT FROM worker_value OR run_row.lease_token IS DISTINCT FROM lease_value OR run_row.input_digest IS DISTINCT FROM input_digest_value OR run_row.cancel_requested OR run_row.lease_expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion lease rejected';
 END IF;
 SELECT * INTO STRICT link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id,test_definition_id,test_definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) FOR SHARE;
 SELECT * INTO STRICT definition_row FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,target_id,target_kind,enabled)=(o,w,e,link_row.test_definition_id,link_row.test_definition_version,link_row.target_id,link_row.target_kind,true) FOR SHARE;
 target_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,link_row.target_id,link_row.target_kind,link_row.test_definition_id,link_row.test_definition_version);
 -- Start and Complete serialize on the same run lock. Every retained receipt
 -- must belong to this exact attempt, input, lease and pinned target snapshot.
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r) AND (attempt<>run_row.attempt OR input_digest IS DISTINCT FROM input_digest_value OR lease_digest IS DISTINCT FROM digest(lease_value,'sha256') OR target_resolution IS DISTINCT FROM target_value OR NOT definition_row.categories ? category)) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion journal conflict';
 END IF;
 total:=jsonb_array_length(definition_row.categories);
 IF objective_value IS DISTINCT FROM 'Evaluate curated categories: '||(SELECT string_agg(value,', ' ORDER BY ordinality) FROM jsonb_array_elements_text(definition_row.categories) WITH ORDINALITY c(value,ordinality)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion objective conflict';END IF;
 IF verdict_value IN('pass','fail') THEN
  IF (SELECT count(*) FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,state,http_status)=(o,w,e,r,'completed',200))<>total THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion observations missing';END IF;
  SELECT count(*) FILTER(WHERE j.protected),jsonb_agg(c.value||CASE WHEN j.protected THEN ': protected' ELSE ': unsafe behavior observed' END ORDER BY c.ordinality) INTO passed,expected_evidence
  FROM jsonb_array_elements_text(definition_row.categories) WITH ORDINALITY c(value,ordinality)
  JOIN public.zasp_security_agent_test_invocations j ON (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.category)=(o,w,e,r,c.value);
  IF verdict_value IS DISTINCT FROM (CASE WHEN passed=total THEN 'pass' ELSE 'fail' END) OR evidence_value IS DISTINCT FROM expected_evidence
   OR behavior_value IS DISTINCT FROM format('%s of %s curated security checks passed; %s exposed unsafe behavior.',passed,total,total-passed) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion verdict conflict';END IF;
 ELSE
  -- Engine error is retained as inconclusive evidence, never a successful test.
  IF NOT COALESCE((behavior_value='The bounded target adapter did not return a complete evaluation.' AND evidence_value='["Target adapter evaluation did not complete"]'::jsonb)
   OR (behavior_value='The bounded Promptfoo engine did not complete the evaluation.' AND evidence_value='["Promptfoo execution did not complete"]'::jsonb),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked completion error rejected';END IF;
 END IF;
 -- Compare the exact uploaded bytes, not a separate caller-selected manifest.
 BEGIN
  artifact_json:=convert_from(artifact_value,'UTF8')::json;
  artifact_doc:=artifact_json::jsonb;
 EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked artifact encoding rejected';
 END;
 IF EXISTS(WITH RECURSIVE nodes(value,depth) AS (
  SELECT artifact_json,0 UNION ALL
  SELECT child.value,n.depth+1 FROM nodes n CROSS JOIN LATERAL (
   SELECT value FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END)
   UNION ALL SELECT value FROM json_array_elements(CASE WHEN json_typeof(n.value)='array' THEN n.value ELSE '[]'::json END)
  ) child WHERE n.depth<=24
 ) SELECT 1 FROM nodes n WHERE depth>24 OR (SELECT count(*)<>count(DISTINCT key) FROM json_each(CASE WHEN json_typeof(n.value)='object' THEN n.value ELSE '{}'::json END))) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked artifact ambiguity rejected';
 END IF;
 native_doc:=artifact_doc->'native_artifact';
 IF jsonb_typeof(artifact_doc) IS DISTINCT FROM 'object' OR artifact_doc->>'schema_version' IS DISTINCT FROM 'red-team-evidence-bundle-v2'
  OR artifact_doc-ARRAY['schema_version','input_artifact','summary','native_artifact']<>'{}'::jsonb
  OR artifact_doc->'input_artifact' IS DISTINCT FROM input_value
  OR artifact_doc->'summary' IS DISTINCT FROM jsonb_build_object('schema_version','red-team-evidence-v2','engine','promptfoo','engine_version','0.121.19','run_id',r,'input_digest',encode(input_digest_value,'hex'),'objective',objective_value,'behavior',behavior_value,'verdict',verdict_value,'error_code',error_value,'evidence',evidence_value)
  OR native_doc->>'schema_version' IS DISTINCT FROM 'red-team-native-artifact-v2' OR native_doc->>'redaction_policy' IS DISTINCT FROM 'red-team-artifact-redaction-v2'
  OR native_doc->>'run_id' IS DISTINCT FROM r OR native_doc->>'input_digest' IS DISTINCT FROM encode(input_digest_value,'hex') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact association conflict';
 END IF;
 IF native_doc->'native_output'='null'::jsonb THEN
  IF verdict_value<>'engine_error' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact observations missing';END IF;
 ELSE
  records:=native_doc#>'{native_output,results,results}';
  IF jsonb_typeof(records) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact observations invalid';END IF;
  IF jsonb_array_length(records)<>total THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact observations incomplete';END IF;
  FOR artifact_item IN SELECT value,ordinality FROM jsonb_array_elements(records) WITH ORDINALITY LOOP
   observed:=artifact_item.value#>'{response,linked_observation}';
   IF artifact_item.value#>>'{vars,category}' IS DISTINCT FROM definition_row.categories->>(artifact_item.ordinality::integer-1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact category conflict';END IF;
   IF observed IS NOT NULL AND observed<>'null'::jsonb THEN
    SELECT jsonb_build_object('target_comparison',j.target_resolution->'comparison','schema_version','red-team-linked-observation-v1','run_id',r,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected)) INTO expected_observation
    FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.category,j.state,j.http_status)=(o,w,e,r,definition_row.categories->>(artifact_item.ordinality::integer-1),'completed',200);
    IF NOT FOUND OR observed IS DISTINCT FROM expected_observation OR artifact_item.value->'success' IS DISTINCT FROM observed#>'{observation,protected}' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact journal conflict';END IF;
   ELSIF verdict_value IN('pass','fail') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked artifact observation missing';
   END IF;
  END LOOP;
 END IF;
 -- Reuse private predecessor persistence, never its public legacy entrypoint.
 -- It remains inaccessible to application roles and receives no new grant.
 result_value:=zasp_existing_tests_predecessor.zasp_red_team_finish_run(o,w,e,r,worker_value,lease_value,input_digest_value,verdict_value,objective_value,behavior_value,error_value,evidence_value,reference_value,key_value,version_value,checksum_value,size_value,input_value);
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='existing test completion release unavailable';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r);
 IF run_row.lease_expires_at<=clock_timestamp() OR parent_deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion authority expired';END IF;
 RETURN result_value;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked completion association rejected';
END
$finish$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea) TO zasp_red_team_worker;

ALTER TABLE public.zasp_security_agent_test_links ADD COLUMN cancellation_outcome text;
ALTER TABLE public.zasp_security_agent_test_links ADD COLUMN cancellation_recorded_at timestamptz;
ALTER TABLE public.zasp_security_agent_test_links ADD CONSTRAINT zasp_existing_test_cancellation_outcome CHECK(
 cancellation_outcome IS NULL AND cancellation_recorded_at IS NULL OR
 cancellation_outcome IS NOT NULL AND cancellation_outcome IN('cancelled_before_execution','cancelled_after_partial_execution','outcome_unknown') AND cancellation_recorded_at IS NOT NULL);

-- Shared by the authenticated human API and exact-lease worker finalization.
-- This revokes execution only. Stopped/expired parents must not prevent it.
-- Callers authorize and hold organization/parent/link locks before entering.
-- Shared transition only; no grant permits workers to bypass those boundaries.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_cancel_transition(o text,w text,e text,r text)
RETURNS public.zasp_red_team_runs LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $transition$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;outcome_value text;
BEGIN
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR run_row.state IN('complete','failed','cancelled') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation state changed';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,state)=(o,w,e,r,'started')) THEN outcome_value:='outcome_unknown';
 ELSIF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r)) THEN outcome_value:='cancelled_after_partial_execution';
 ELSE outcome_value:='cancelled_before_execution';END IF;
 UPDATE public.zasp_red_team_runs SET version=version+1,cancel_requested=true,state=CASE WHEN outcome_value='outcome_unknown' THEN 'failed' ELSE 'cancelled' END,error_code=CASE WHEN outcome_value='outcome_unknown' THEN 'outcome_unknown' ELSE 'cancelled' END,completed_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp()
 WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO run_row;
 UPDATE public.zasp_security_agent_test_links SET cancellation_outcome=outcome_value,cancellation_recorded_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r) AND cancellation_outcome IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation receipt conflict';END IF;
 RETURN run_row;
END
$transition$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_cancel_transition(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_cancel_transition(text,text,text,text) FROM PUBLIC;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_cancel_core(o text,w text,e text,r text,expected_version bigint,worker_value text,lease_value bytea,input_value bytea)
RETURNS public.zasp_red_team_runs LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cancel$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;link_row public.zasp_security_agent_test_links%ROWTYPE;linked boolean;outcome_value text;checksum_value text;fingerprint_value text;original_lease_expires_at timestamptz;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='linked cancellation input rejected';END IF;
 IF worker_value IS NULL THEN
  IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_api') AND expected_version BETWEEN 1 AND 999999 AND lease_value IS NULL AND input_value IS NULL,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked cancellation principal rejected';END IF;
 ELSE
  IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker') AND worker_value~'^[a-z][a-z0-9.-]{2,127}$' AND octet_length(lease_value)=32 AND octet_length(input_value)=32 AND expected_version IS NULL,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='linked cancellation principal rejected';END IF;
 END IF;
 SELECT value INTO checksum_value FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_checksum';
 SELECT value INTO fingerprint_value FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_fingerprint';
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked cancellation release unavailable';END IF;
 SELECT * INTO link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r);
 linked:=FOUND;
 IF linked THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
  PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
  PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link_row.run_id) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation parent unavailable';END IF;
  SELECT * INTO STRICT link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id,run_id,step_id)=(o,w,e,r,link_row.run_id,link_row.step_id) FOR UPDATE;
 ELSIF worker_value IS NOT NULL THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation association unavailable';
 END IF;
 SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='red team run not found';END IF;
 IF run_row.state IN('complete','failed','cancelled') OR worker_value IS NULL AND run_row.version IS DISTINCT FROM expected_version
  OR worker_value IS NOT NULL AND (run_row.state<>'leased' OR run_row.worker_id IS DISTINCT FROM worker_value OR run_row.lease_token IS DISTINCT FROM lease_value OR run_row.input_digest IS DISTINCT FROM input_value OR NOT run_row.cancel_requested OR run_row.lease_expires_at<=clock_timestamp()) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation authority changed';
 END IF;
 original_lease_expires_at:=run_row.lease_expires_at;
 IF linked THEN
  SELECT * INTO STRICT run_row FROM public.zasp_production_security_agent_existing_tests_cancel_transition(o,w,e,r);
 ELSE
  -- Preserve the legacy human API's queued/retryable versus leased behavior.
  UPDATE public.zasp_red_team_runs SET version=version+1,cancel_requested=true,state=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE state END,completed_at=CASE WHEN state IN('queued','retryable') THEN transaction_timestamp() ELSE completed_at END,error_code=CASE WHEN state IN('queued','retryable') THEN 'cancelled' ELSE error_code END,updated_at=transaction_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO run_row;
 END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked cancellation release unavailable';END IF;
 IF worker_value IS NOT NULL AND (original_lease_expires_at IS NULL OR original_lease_expires_at<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='linked cancellation lease expired';END IF;
 RETURN run_row;
END
$cancel$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_cancel_core(text,text,text,text,bigint,text,bytea,bytea) FROM PUBLIC;

DO $human_cancel$
DECLARE source_value text;start_value integer;end_value integer;replacement_value text;
BEGIN
 source_value:=pg_get_functiondef('public.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text)'::regprocedure);
 EXECUTE replace(source_value,'FUNCTION public.zasp_red_team_cancel_run(','FUNCTION zasp_existing_tests_predecessor.zasp_red_team_cancel_run(');
 ALTER FUNCTION zasp_existing_tests_predecessor.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.zasp_red_team_cancel_run(text,text,text,text,text,text,bigint,text) FROM PUBLIC;
 start_value:=strpos(source_value,'UPDATE zasp_red_team_runs SET version=version+1,cancel_requested=true');
 end_value:=strpos(source_value,'result_value:=zasp_red_team_mutation_result(');
 IF start_value=0 OR end_value<=start_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='human cancellation predecessor rejected';END IF;
 replacement_value:='SELECT * INTO STRICT row_value FROM public.zasp_production_security_agent_existing_tests_cancel_core(organization_value,workspace_value,environment_value,run_value,expected_version_value,NULL,NULL,NULL);';
 EXECUTE overlay(source_value placing replacement_value from start_value for end_value-start_value);
END
$human_cancel$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_worker_cancel(o text,w text,e text,r text,worker_value text,lease_value bytea,input_value bytea,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $worker$
DECLARE run_row public.zasp_red_team_runs%ROWTYPE;outcome_value text;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked cancellation release unavailable';END IF;
 SELECT * INTO run_row FROM public.zasp_production_security_agent_existing_tests_cancel_core(o,w,e,r,NULL,worker_value,lease_value,input_value);
 SELECT cancellation_outcome INTO STRICT outcome_value FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r);
 RETURN jsonb_build_object('run',public.zasp_red_team_run_json(run_row),'cancellation_outcome',outcome_value);
END
$worker$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_cancel(text,text,text,text,text,bytea,bytea,text,text) TO zasp_red_team_worker;

-- Classification is read-only, not execution authorization. Both selected
-- protocols independently fence their actual mutations against durable links.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_worker_protocol(o text,w text,e text,r text,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $protocol$
DECLARE protocol_value text;
BEGIN
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker protocol release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker protocol input rejected';END IF;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)=(o,w,e,r)) THEN 'linked' ELSE 'legacy' END INTO protocol_value
 FROM public.zasp_red_team_runs t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker protocol run unavailable';END IF;
 IF NOT COALESCE(public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker protocol release unavailable';END IF;
 RETURN jsonb_build_object('protocol',protocol_value);
END
$protocol$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_worker_protocol(text,text,text,text,text,text) TO zasp_red_team_worker;
