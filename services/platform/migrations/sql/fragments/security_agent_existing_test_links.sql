-- Private transactional persistence only. The future guarded dispatch caller
-- must own organization admission, lease/policy/budget checks and effect creation.
-- No application EXECUTE grant exists until the full invocation protocol ships.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(o text,w text,e text,r text,s text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorize$
DECLARE run_row public.zasp_security_agent_runs%ROWTYPE;step_row public.zasp_security_agent_steps%ROWTYPE;
 plan_row public.zasp_security_agent_plans%ROWTYPE;definition_row public.zasp_security_agent_definitions%ROWTYPE;
 approval_row public.zasp_security_agent_approvals%ROWTYPE;item jsonb;authorization_value text;
BEGIN
 -- Private caller already owns organization admission and current run lease.
 -- Keep prerequisite locks until enqueue and audit have both completed.
 SELECT * INTO run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,r,'planning') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test run authorization changed';END IF;
 SELECT * INTO plan_row FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)=(o,w,e,r,run_row.definition_id,run_row.definition_version) FOR SHARE;
 IF NOT FOUND OR plan_row.plan_hash IS DISTINCT FROM run_row.plan_hash OR plan_row.plan_hash IS DISTINCT FROM digest(convert_to(plan_row.plan::text,'UTF8'),'sha256')
  OR plan_row.expires_at<=clock_timestamp() OR jsonb_typeof(plan_row.plan->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(plan_row.plan->'steps')<>1 THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test plan authorization changed';END IF;
 SELECT * INTO step_row FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,state)=(o,w,e,r,s,0,'authorized') FOR UPDATE;
 item:=plan_row.plan->'steps'->0;
 IF NOT FOUND OR step_row.action_key NOT IN('run_test','rerun_test') OR step_row.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test step authorization changed';END IF;
 SELECT * INTO definition_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,run_row.definition_id,run_row.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR definition_row.activation NOT IN('supervised','autonomous') OR definition_row.body->>'autonomy' IS DISTINCT FROM definition_row.activation
  OR definition_row.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR definition_row.body->'allowed_actions' IS DISTINCT FROM jsonb_build_array(step_row.action_key)
  OR definition_row.body->>'verification_kind' IS DISTINCT FROM 'test_run' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test definition authorization changed';END IF;
 authorization_value:=CASE definition_row.activation WHEN 'supervised' THEN 'approval_required' ELSE 'autonomous' END;
 IF step_row.authorization_result IS DISTINCT FROM authorization_value OR item IS DISTINCT FROM jsonb_build_object(
  'step_id',s,'index',0,'action',step_row.action_key,'target_id',definition_row.body->'existing_test'->>'definition_id',
  'test_definition_version',definition_row.body->'existing_test'->'definition_version','test_target_id',item->>'test_target_id',
  'test_target_kind',item->>'test_target_kind','authorization',authorization_value) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test authorization binding changed';END IF;
 SELECT * INTO approval_row FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 IF definition_row.activation='supervised' THEN
  IF NOT FOUND OR approval_row.state<>'approved' OR approval_row.plan_hash IS DISTINCT FROM plan_row.plan_hash
   OR approval_row.requester_id IS DISTINCT FROM run_row.requested_by OR approval_row.approver_id IS NULL
   OR approval_row.approver_id=approval_row.requester_id OR approval_row.fresh_auth_at IS NULL
   OR approval_row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='existing test approval unavailable';END IF;
 ELSIF EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='autonomous test approval unexpected';
 END IF;
END
$authorize$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_authorize_step(text,text,text,text,text) FROM PUBLIC;

CREATE TABLE public.zasp_security_agent_test_links (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 run_id text NOT NULL,step_id text NOT NULL,action_key text NOT NULL CHECK(action_key IN('run_test','rerun_test')),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 test_definition_id text NOT NULL,test_definition_version bigint NOT NULL CHECK(test_definition_version BETWEEN 1 AND 1000000),
 test_run_id text NOT NULL,target_id text NOT NULL,target_kind text NOT NULL,
 test_categories jsonb NOT NULL CHECK(jsonb_typeof(test_categories)='array' AND jsonb_array_length(test_categories) BETWEEN 1 AND 6),
 baseline jsonb CHECK(baseline IS NULL OR jsonb_typeof(baseline)='object'),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id,action_key) REFERENCES public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id)
);
ALTER TABLE public.zasp_security_agent_test_links OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_test_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_test_links FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_test_links_authority ON public.zasp_security_agent_test_links TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_security_agent_test_links FROM PUBLIC,zasp_discovery_api,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_outbox_worker,zasp_red_team_adapter;

CREATE FUNCTION public.zasp_security_agent_test_link_enqueue(o text,w text,e text,r text,s text,c text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public
AS $link$
DECLARE run_row public.zasp_security_agent_runs%ROWTYPE;step_row public.zasp_security_agent_steps%ROWTYPE;
 prior public.zasp_security_agent_test_links%ROWTYPE;body_value jsonb;binding jsonb;actor_value text;test_run text;result_value jsonb;baseline_value jsonb;baseline_cutoff timestamptz;categories_value jsonb;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s) AND public.zasp_valid_product_id(c),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test link input rejected';
 END IF;
 SELECT * INTO run_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link intent changed';END IF;
 SELECT * INTO step_row FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 IF NOT FOUND OR step_row.action_key NOT IN('run_test','rerun_test') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link intent changed';END IF;
 SELECT * INTO prior FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF FOUND THEN
  IF prior.action_key IS DISTINCT FROM step_row.action_key OR prior.input_digest IS DISTINCT FROM step_row.input_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link replay conflict';END IF;
  RETURN prior.result||jsonb_build_object('replayed',true);
 END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,s);
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state)=(o,w,e,r,s,step_row.action_key,step_row.input_digest,'pending') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link effect missing';END IF;
 SELECT body INTO body_value FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,run_row.definition_id,run_row.definition_version) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR body_value->'allowed_actions' IS DISTINCT FROM jsonb_build_array(step_row.action_key) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link definition changed';END IF;
 SELECT actor_id INTO actor_value FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,run_row.definition_id,run_row.definition_version) FOR SHARE;
 IF NOT FOUND OR NOT COALESCE(public.zasp_valid_product_id(actor_value),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link actor unavailable';END IF;
 test_run:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_run',r||chr(31)||s||chr(31)||step_row.action_key);
 -- Match the shared human/API core's advisory-before-test-definition order.
 -- Take all such blocking locks before the resolver's wall-clock checks.
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor_value,'runTest','agent-step:'||test_run),0));
 -- Enqueue's existing core takes a write lock on the definition. Take that
 -- lock before the resolver's SHARE lock, avoiding concurrent lock upgrades.
 PERFORM 1 FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,body_value->'existing_test'->>'definition_id') FOR UPDATE;
 binding:=public.zasp_production_security_agent_run_context_test_binding(o,w,e,run_row.definition_id,run_row.definition_version);
 SELECT categories INTO STRICT categories_value FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,binding->>'definition_id',(binding->>'definition_version')::bigint);
 -- queued_at defaults to transaction start and can predate lock waits. Use
 -- the wall-clock pre-enqueue boundary and snapshot before creating new work.
 baseline_cutoff:=clock_timestamp();
 -- Snapshot committed completion receipts visible at enqueue. Do not lock old
 -- runs here: completion locks run before definition, and we own definition.
 -- This is a candidate, not remediation proof. Settlement must retrieve both
 -- immutable objects and validate their full comparison/evaluation identities.
 -- A legacy candidate lacking comparison data must not be replaced by an older
 -- comparable result merely to manufacture a fail-to-pass claim.
 SELECT jsonb_build_object('schema_version','security-agent-test-baseline-v1',
  'run_id',a.run_id,'attempt',a.attempt,'input_digest',encode(a.input_digest,'hex'),
  'completed_at',to_char(a.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_artifact',a.input_artifact,
  'output_artifact',jsonb_build_object('reference',a.evidence_reference,'key',a.evidence_key,
   'version_id',a.evidence_version_id,'sha256',encode(a.evidence_checksum,'hex'),'size_bytes',a.evidence_size))
 INTO baseline_value
 FROM public.zasp_red_team_runs b
 JOIN public.zasp_red_team_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(b.organization_id,b.workspace_id,b.environment_id,b.run_id,b.attempt)
 WHERE (b.organization_id,b.workspace_id,b.environment_id,b.definition_id,b.definition_version,b.state,b.verdict)=
  (o,w,e,binding->>'definition_id',(binding->>'definition_version')::bigint,'complete','fail')
 AND b.run_id<>test_run AND b.completed_at<baseline_cutoff AND a.completed_at=b.completed_at
 AND b.error_code IS NULL AND a.error_code IS NULL
 AND (a.input_digest,a.verdict,a.evidence_reference,a.evidence_key,a.evidence_version_id,a.evidence_checksum,a.evidence_size)=
  (b.input_digest,b.verdict,b.evidence_reference,b.evidence_key,b.evidence_version_id,b.evidence_checksum,b.evidence_size)
 AND public.zasp_red_team_valid_input_artifact(o,w,e,a.input_artifact)
 AND a.evidence_checksum<>decode(repeat('00',32),'hex')
 AND public.zasp_discovery_s3_object_reference(a.evidence_reference)
 AND a.evidence_key='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||b.run_id
 AND substring(a.evidence_reference FROM '^s3://[^/]+/(.+)$')=a.evidence_key
 AND a.input_artifact->>'reference'<>a.evidence_reference
 AND length(a.evidence_version_id) BETWEEN 1 AND 512 AND a.evidence_version_id!~'[[:space:][:cntrl:]]'
 ORDER BY b.completed_at DESC,b.run_id DESC,a.attempt DESC LIMIT 1;
 result_value:=public.zasp_security_agent_test_enqueue_core(o,w,e,actor_value,'agent-step:'||test_run,binding->>'definition_id',(binding->>'definition_version')::bigint,test_run,c);
 -- Only an existing agent link can authorize replay. A colliding human/API
 -- receipt must not be adopted as new Security Agent provenance.
 IF result_value->'replayed' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test link enqueue conflict';END IF;
 -- A uniqueness/FK wait inside enqueue is also time spent. Recheck while the
 -- prerequisite rows remain locked; failure rolls back run/outbox/receipt too.
 PERFORM public.zasp_production_security_agent_run_context_test_binding(o,w,e,run_row.definition_id,run_row.definition_version);
 PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,s);
 result_value:=jsonb_build_object('test_run_id',test_run,'definition_id',binding->>'definition_id','definition_version',(binding->>'definition_version')::bigint,'state','pending','replayed',false);
 INSERT INTO public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,test_definition_id,test_definition_version,test_run_id,target_id,target_kind,test_categories,baseline,result)
 VALUES(o,w,e,r,s,step_row.action_key,step_row.input_digest,binding->>'definition_id',(binding->>'definition_version')::bigint,test_run,binding->>'target_id',binding->>'target_kind',categories_value,baseline_value,result_value);
 PERFORM public.zasp_production_security_agent_existing_tests_authorize_step(o,w,e,r,s);
 RETURN result_value;
END
$link$;
ALTER FUNCTION public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_test_link_enqueue(text,text,text,text,text,text) FROM PUBLIC;
