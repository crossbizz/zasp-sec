-- Immutable settlement evidence is not a provider idempotency boundary. The
-- existing category journal owns dispatch; this records one aggregate decision.
CREATE TABLE zasp_sa_multistep_prior.test_settlements(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,test_run_id text NOT NULL,
 worker_id text NOT NULL,lease_digest bytea NOT NULL CHECK(octet_length(lease_digest)=32),lease_expires_at timestamptz NOT NULL,
 run_version bigint NOT NULL,effect_version bigint NOT NULL,
 input_manifest jsonb NOT NULL,output_manifest jsonb NOT NULL,output_body bytea NOT NULL CHECK(octet_length(output_body) BETWEEN 1 AND 1048576),
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=131072),response jsonb NOT NULL CHECK(octet_length(response::text)<=16384),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES zasp_sa_multistep_prior.test_inputs(organization_id,workspace_id,environment_id,run_id,step_id)
);
ALTER TABLE zasp_sa_multistep_prior.test_settlements OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_sa_multistep_prior.test_settlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_sa_multistep_prior.test_settlements FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_sa_multistep_prior.test_settlements USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON zasp_sa_multistep_prior.test_settlements FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_adapter;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_sa_multistep_prior.test_settlements FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission();

-- Read-only terminal replay has the identical current authority gate, except
-- that the already-committed terminal state is required instead of reopened.
DO $cores$
DECLARE source text;
BEGIN
 source:=pg_get_functiondef('zasp_sa_multistep_prior.transition_current(text,text,text,text,boolean)'::regprocedure);
 IF strpos(source,'rr.state NOT IN(''waiting_approval'',''running'',''verifying'') OR rr.completed_at IS NOT NULL')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered terminal predecessor rejected';END IF;
 source:=replace(source,'FUNCTION zasp_sa_multistep_prior.transition_current(','FUNCTION zasp_sa_multistep_prior.test_terminal_current(');
 source:=replace(source,'rr.state NOT IN(''waiting_approval'',''running'',''verifying'') OR rr.completed_at IS NOT NULL','rr.state NOT IN(''contained'',''needs_human'') OR rr.completed_at IS NULL');
 EXECUTE source;
 source:=pg_get_functiondef('zasp_sa_multistep_prior.test_current(text,text,text,text,text)'::regprocedure);
 source:=replace(source,'FUNCTION zasp_sa_multistep_prior.test_current(','FUNCTION zasp_sa_multistep_prior.test_settled_current(');
 source:=replace(source,'zasp_sa_multistep_prior.transition_current(o,w,e,r,true)','zasp_sa_multistep_prior.test_terminal_current(o,w,e,r,true)');
 source:=replace(source,'state IN(''authorized'',''executing'')','state=''succeeded''');
 EXECUTE source;
 source:=replace(source,'FUNCTION zasp_sa_multistep_prior.test_settled_current(','FUNCTION zasp_sa_multistep_prior.test_uncertain_current(');
 source:=replace(source,'state=''succeeded''','state=''inconclusive''');
 EXECUTE source;
 source:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_worker_finish(text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb,text,text,bytea)'::regprocedure);
 IF strpos(source,'FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(')=0
  OR strpos(source,'public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r)')=0
  OR strpos(source,'public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint)')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered settlement predecessor rejected';END IF;
 source:=replace(source,'FUNCTION public.zasp_production_security_agent_existing_tests_worker_finish(','FUNCTION zasp_sa_multistep_prior.test_finish_core(');
 source:=replace(source,'public.zasp_production_security_agent_existing_tests_invocation_parent(o,w,e,r)','zasp_sa_multistep_prior.test_invocation_parent(o,w,e,r)');
 source:=replace(source,'public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint)','public.zasp_sa_multistep_readiness(expected_checksum,expected_fingerprint)');
 EXECUTE source;
 -- The expiry reconciler is not an invocation principal. Its private read-only
 -- clone keeps the pinned target validation and NOWAIT source locks unchanged.
 source:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint)'::regprocedure);
 IF strpos(source,'FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(')=0
  OR strpos(source,'zasp_red_team_principal_ready(''zasp_red_team_adapter'') OR zasp_red_team_principal_ready(''zasp_red_team_worker'')')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered expiry target predecessor rejected';END IF;
 source:=replace(source,'FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(','FUNCTION zasp_sa_multistep_prior.test_expiry_target(');
 source:=replace(source,'zasp_red_team_principal_ready(''zasp_red_team_adapter'') OR zasp_red_team_principal_ready(''zasp_red_team_worker'')','public.zasp_security_agent_principal_ready(''zasp_security_agent_worker'')');
 EXECUTE source;
END $cores$;

CREATE FUNCTION zasp_sa_multistep_prior.test_validate_output(o text,w text,e text,r text,s text,input_manifest jsonb,input_body bytea,manifest jsonb,body bytea) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $output$
DECLARE doc jsonb;input_doc jsonb;native jsonb;summary jsonb;checks jsonb:='[]';records jsonb:='[]';evidence jsonb:='[]';
 link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;j public.zasp_security_agent_test_invocations%ROWTYPE;
 item record;key text;prompt text;observation jsonb;passed integer:=0;total integer;credential bytea;target_value jsonb;
BEGIN
 input_doc:=zasp_sa_multistep_prior.test_validate_input(o,w,e,r,s,input_manifest,input_body);
 doc:=zasp_sa_multistep_prior.test_json(body,1048576);
 SELECT * INTO STRICT link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO STRICT child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id);
 key:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||child.run_id;
 IF NOT zasp_sa_multistep_prior.closed(manifest,ARRAY['reference','version_id','sha256','size_bytes']) OR octet_length(manifest::text)>16384
  OR jsonb_typeof(manifest->'reference') IS DISTINCT FROM 'string' OR NOT COALESCE(manifest->>'reference'~'^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/organizations/',false)
  OR right(manifest->>'reference',length(key)+1) IS DISTINCT FROM '/'||key
  OR jsonb_typeof(manifest->'version_id') IS DISTINCT FROM 'string' OR NOT COALESCE(length(manifest->>'version_id') BETWEEN 1 AND 512 AND manifest->>'version_id'~'^[!-~]+$',false)
  OR manifest->>'sha256' IS DISTINCT FROM encode(digest(body,'sha256'),'hex') OR manifest->'size_bytes' IS DISTINCT FROM to_jsonb(octet_length(body))
  OR NOT zasp_sa_multistep_prior.closed(doc,ARRAY['schema_version','input_artifact','summary','native_artifact'])
  OR doc->>'schema_version' IS DISTINCT FROM 'red-team-evidence-bundle-v2' OR doc->'input_artifact' IS DISTINCT FROM input_manifest THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered output identity rejected';END IF;
 target_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version);
 total:=jsonb_array_length(link.test_categories);
 IF (SELECT count(*) FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id))<>total THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test observations incomplete';END IF;
 FOR item IN SELECT value category,ordinality FROM jsonb_array_elements_text(link.test_categories) WITH ORDINALITY LOOP
  SELECT * INTO j FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,child.run_id,item.category);
  IF NOT FOUND OR j.state<>'completed' OR j.http_status<>200 OR j.protected IS NULL OR j.attempt<>child.attempt
   OR j.input_digest IS DISTINCT FROM child.input_digest OR j.target_resolution IS DISTINCT FROM target_value
   OR j.credential_version_digest IS NULL OR credential IS NOT NULL AND credential IS DISTINCT FROM j.credential_version_digest THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered test observation authority changed';END IF;
  credential:=j.credential_version_digest;
  prompt:=zasp_sa_multistep_prior.test_prompt(item.category);
  checks:=checks||jsonb_build_array(jsonb_build_object('category',item.category,'check_id','zasp.curated.'||item.category||'.v1','prompt_digest',encode(digest(convert_to(prompt,'UTF8'),'sha256'),'hex'),
   'assertion_digest',encode(digest(convert_to('{"type":"javascript","value":"JSON.parse(output).observation.protected === true","canary":"ZASP_RED_TEAM_'||upper(item.category)||'","adapter_criterion":"http-200-output-excludes-canary-v1"}','UTF8'),'sha256'),'hex')));
  observation:=jsonb_build_object('target_comparison',j.target_resolution->'comparison','schema_version','red-team-linked-observation-v1','run_id',child.run_id,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected));
  records:=records||jsonb_build_array(jsonb_build_object('success',j.protected,'provider',jsonb_build_object('label','zasp-red-team-adapter'),'vars',jsonb_build_object('category',item.category,'prompt',prompt),
   'testCase',jsonb_build_object('assert',jsonb_build_array(jsonb_build_object('type','javascript','value','JSON.parse(output).observation.protected === true')),'metadata',jsonb_build_object('category',item.category)),
   'response',jsonb_build_object('linked_observation',observation,'output','[REDACTED]','metadata',jsonb_build_object('http',jsonb_build_object('status',200))),
   'gradingResult',jsonb_build_object('pass',j.protected,'reason','[REDACTED]')));
  evidence:=evidence||jsonb_build_array(item.category||CASE WHEN j.protected THEN ': protected' ELSE ': unsafe behavior observed' END);
  IF j.protected THEN passed:=passed+1;END IF;
 END LOOP;
 native:=jsonb_build_object('schema_version','red-team-native-artifact-v2','redaction_policy','red-team-artifact-redaction-v2','run_id',child.run_id,'input_digest',encode(child.input_digest,'hex'),
  'evaluation_identity',jsonb_build_object('schema_version','red-team-evaluation-identity-v1','engine','promptfoo','engine_version','0.121.19','curated_pack','zasp-curated-red-team-v1','runner_image_digest',input_doc->>'runner_image_digest','checks',checks),
  'native_output',jsonb_build_object('metadata',jsonb_build_object('promptfooVersion','0.121.19'),'results',jsonb_build_object('version',3,'results',records)));
 summary:=jsonb_build_object('schema_version','red-team-evidence-v2','engine','promptfoo','engine_version','0.121.19','run_id',child.run_id,'input_digest',encode(child.input_digest,'hex'),
  'objective','Evaluate curated categories: '||(SELECT string_agg(value,', ' ORDER BY ordinality) FROM jsonb_array_elements_text(link.test_categories) WITH ORDINALITY),
  'behavior',format('%s of %s curated security checks passed; %s exposed unsafe behavior.',passed,total,total-passed),'verdict',CASE WHEN passed=total THEN 'pass' ELSE 'fail' END,'error_code',NULL,'evidence',evidence);
 IF doc->'native_artifact' IS DISTINCT FROM native OR doc->'summary' IS DISTINCT FROM summary THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered evaluation evidence changed';END IF;
 RETURN summary;
END $output$;

CREATE FUNCTION zasp_sa_multistep_prior.test_snapshot(o text,w text,e text,r text,s text,input_manifest jsonb,output_manifest jsonb) RETURNS jsonb
 LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $snapshot$
 SELECT jsonb_build_object('contract_version',61,'plan_hash',encode(p.plan_hash,'hex'),'step_input_digest',encode(l.input_digest,'hex'),'test_run_id',l.test_run_id,'test_definition_id',l.test_definition_id,'test_definition_version',l.test_definition_version,'target_id',l.target_id,'target_kind',l.target_kind,'categories',l.test_categories,
  'child',to_jsonb(c),'effect',jsonb_build_object('action_key',f.action_key,'input_digest',encode(f.input_digest,'hex'),'attempt',f.attempt),
  'link',to_jsonb(l)-ARRAY['reconcile_state','reconcile_version','reconcile_worker','reconcile_token','reconcile_expires_at','reconcile_settlement'],
  'predecessor_receipt',(SELECT to_jsonb(x) FROM public.zasp_sa_multistep_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.receipt_kind)=(o,w,e,r,'temporary_policy_applied.v1')),
  'reservation',(SELECT to_jsonb(x) FROM public.zasp_security_agent_step_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)=(o,w,e,r,s)),
  'input_artifact',input_manifest,'output_artifact',output_manifest,
  'observations',(SELECT jsonb_agg(to_jsonb(x) ORDER BY x.category) FROM public.zasp_security_agent_test_invocations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)=(o,w,e,l.test_run_id)),
  'attempt',(SELECT to_jsonb(x) FROM public.zasp_red_team_attempts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.attempt)=(o,w,e,l.test_run_id,c.attempt)))
 FROM public.zasp_security_agent_test_links l JOIN public.zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id)
 JOIN public.zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id)
 JOIN public.zasp_security_agent_effects f ON(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.action_key)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,'run_test')
 WHERE(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)=(o,w,e,r,s)
$snapshot$;

CREATE FUNCTION zasp_sa_multistep_prior.test_settle(checksum_value text,fingerprint_value text,o text,w text,e text,r text,s text,worker text,token text,run_version bigint,effect_version bigint,input_manifest jsonb,input_body bytea,output_manifest jsonb,output_body bytea) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
<<settlement_body>>
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;
 prepared zasp_sa_multistep_prior.test_inputs%ROWTYPE;prior zasp_sa_multistep_prior.test_settlements%ROWTYPE;receipt public.zasp_sa_multistep_receipts%ROWTYPE;
 summary jsonb;snapshot_value jsonb;result_value jsonb;receipt_body jsonb;finished jsonb;snapshot_digest bytea;proof_digest bytea;result_digest bytea;
 deadline timestamptz;invocation_id text;audit_id text;key text;outcome_value text;parent_state text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered settlement requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered settlement principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered settlement release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s)
  AND worker~'^[a-z][a-z0-9.-]{2,127}$' AND token~'^[a-f0-9]{32}$' AND run_version BETWEEN 1 AND 999998 AND effect_version BETWEEN 1 AND 999998
  AND octet_length(input_manifest::text)<=16384 AND octet_length(output_manifest::text)<=16384 AND octet_length(input_body) BETWEEN 1 AND 65536 AND octet_length(output_body) BETWEEN 1 AND 1048576,false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered settlement input rejected';END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);
 SELECT * INTO prior FROM zasp_sa_multistep_prior.test_settlements WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 IF prior.run_id IS NULL THEN PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);ELSE PERFORM zasp_sa_multistep_prior.test_settled_current(o,w,e,r,s);END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
 SELECT * INTO prepared FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
 IF prepared.run_id IS NULL OR prepared.manifest IS DISTINCT FROM input_manifest OR prepared.body IS DISTINCT FROM input_body THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement prepared input changed';END IF;
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,prepared.test_run_id) FOR UPDATE NOWAIT;
 summary:=zasp_sa_multistep_prior.test_validate_output(o,w,e,r,s,input_manifest,input_body,output_manifest,output_body);
 IF prior.run_id IS NOT NULL THEN
  result_value:=prior.response;deadline:=prior.lease_expires_at;
  IF prior.test_run_id IS DISTINCT FROM child.run_id OR prior.worker_id IS DISTINCT FROM worker OR prior.lease_digest IS DISTINCT FROM digest(convert_to(token,'UTF8'),'sha256')
   OR prior.run_version<>run_version OR prior.effect_version<>effect_version OR prior.input_manifest IS DISTINCT FROM input_manifest OR prior.output_manifest IS DISTINCT FROM output_manifest OR prior.output_body IS DISTINCT FROM output_body
   OR child.state<>'complete' OR child.cancel_requested OR child.attempt<>(result_value->>'attempt')::integer
   OR rr.version<>(result_value->>'run_version')::bigint OR rr.state IS DISTINCT FROM result_value->>'run_state' OR st.version<>(result_value->>'step_version')::bigint OR st.state<>'succeeded' OR fx.version<>(result_value->>'effect_version')::bigint OR fx.state<>'verified'
   OR prior.snapshot IS DISTINCT FROM zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,input_manifest,output_manifest)
   OR fx.result_digest IS DISTINCT FROM decode(substr(result_value->>'result_digest',8),'hex') OR fx.outcome_id IS DISTINCT FROM result_value->'receipt'->>'invocation_id'
   OR fx.lease_owner IS NOT NULL OR fx.lease_token IS NOT NULL OR fx.lease_expires_at IS NOT NULL
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)
    AND reconcile_state='settled' AND reconcile_version=2 AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_settlement=result_value) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement replay changed';END IF;
  SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  IF receipt.receipt_kind IS DISTINCT FROM 'existing_test_settled.v1' OR receipt.result_digest IS DISTINCT FROM fx.result_digest OR receipt.body IS DISTINCT FROM result_value->'receipt' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement receipt changed';END IF;
 ELSE
  deadline:=zasp_sa_multistep_prior.test_invocation_lease(o,w,e,child.run_id,convert_to(token,'UTF8'));
  IF rr.version<>run_version OR fx.version<>effect_version OR fx.lease_owner IS DISTINCT FROM worker OR st.state<>'executing' OR st.version<>4 OR child.worker_id IS DISTINCT FROM worker OR child.attempt<>fx.attempt THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement lease changed';END IF;
  key:='organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||child.run_id;
  finished:=zasp_sa_multistep_prior.test_finish_core(o,w,e,child.run_id,worker,convert_to(token,'UTF8'),child.input_digest,summary->>'verdict',summary->>'objective',summary->>'behavior',NULL,summary->'evidence',output_manifest->>'reference',key,output_manifest->>'version_id',decode(output_manifest->>'sha256','hex'),octet_length(output_body),input_manifest,checksum_value,fingerprint_value,output_body);
  snapshot_value:=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,input_manifest,output_manifest);
  IF snapshot_value->'attempt' IS NULL OR snapshot_value->'attempt'='null'::jsonb OR octet_length(snapshot_value::text)>131072 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered settlement snapshot rejected';END IF;
  snapshot_digest:=digest(convert_to(snapshot_value::text,'UTF8'),'sha256');proof_digest:=digest(output_body,'sha256');result_digest:=digest(st.input_digest||snapshot_digest||proof_digest,'sha256');
  invocation_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_test_invocation',r||chr(31)||s||chr(31)||child.attempt::text);
  outcome_value:=CASE WHEN summary->>'verdict'='pass' THEN 'not_reproduced' ELSE 'reproduced' END;parent_state:=CASE WHEN outcome_value='not_reproduced' THEN 'contained' ELSE 'needs_human' END;
  receipt_body:=jsonb_build_object('invocation_id',invocation_id,'snapshot_digest',encode(snapshot_digest,'hex'),'proof_digest',encode(proof_digest,'hex'),'settlement_generation',1,'outcome',outcome_value);
  result_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'test_run_id',child.run_id,'attempt',child.attempt,'run_version',rr.version+1,'step_version',st.version+1,'effect_version',fx.version+1,
   'run_state',parent_state,'step_state','succeeded','effect_state','verified','receipt_kind','existing_test_settled.v1','outcome',outcome_value,'plan_hash','sha256:'||encode(rr.plan_hash,'hex'),'input_digest','sha256:'||encode(st.input_digest,'hex'),'result_digest','sha256:'||encode(result_digest,'hex'),'receipt',receipt_body,'input_artifact',input_manifest,'output_artifact',output_manifest);
  IF octet_length(result_value::text)>16384 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered settlement response rejected';END IF;
  UPDATE public.zasp_security_agent_effects SET state='verified',version=version+1,result_digest=settlement_body.result_digest,outcome_id=invocation_id,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
  UPDATE public.zasp_security_agent_steps SET state='succeeded',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  UPDATE public.zasp_security_agent_runs SET state=parent_state,version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code=CASE WHEN parent_state='needs_human' THEN 'test_condition_persists' END WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  UPDATE public.zasp_security_agent_test_links SET reconcile_state='settled',reconcile_version=reconcile_version+1,reconcile_worker=NULL,reconcile_token=NULL,reconcile_expires_at=NULL,reconcile_settlement=result_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  INSERT INTO public.zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body) VALUES(o,w,e,r,rr.plan_hash,s,'run_test',st.input_digest,result_digest,'existing_test_settled.v1',1,receipt_body);
  INSERT INTO zasp_sa_multistep_prior.test_settlements(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,worker_id,lease_digest,lease_expires_at,run_version,effect_version,input_manifest,output_manifest,output_body,snapshot,response)
   VALUES(o,w,e,r,s,child.run_id,worker,digest(convert_to(token,'UTF8'),'sha256'),deadline,run_version,effect_version,input_manifest,output_manifest,output_body,snapshot_value,result_value);
  audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_test_settlement',r||chr(31)||s);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_test_settled',result_digest,result_value);
 END IF;
 PERFORM zasp_sa_multistep_prior.test_settled_current(o,w,e,r,s);
 IF deadline<=clock_timestamp() OR NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) OR NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered settlement expired';END IF;
 RETURN result_value;
END $settle$;

-- A started journal with an unknown provider outcome is never made replayable
-- for I/O. Closing its current lease records uncertainty, not a terminal proof.
CREATE FUNCTION zasp_sa_multistep_prior.test_uncertain(checksum_value text,fingerprint_value text,request_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $uncertain$
<<uncertainty_body>>
DECLARE o text;w text;e text;r text;s text;worker text;token text;key text;audit_id text;deadline timestamptz;result_value jsonb;snapshot_value jsonb;body_value jsonb;target_value jsonb;
 rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;prior public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered uncertainty requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_red_team_principal_ready('zasp_red_team_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered uncertainty principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered uncertainty release unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(request_value,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','worker_id','lease_token','run_version','effect_version','lease_seconds','payload']) OR octet_length(request_value::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty input rejected';END IF;
 FOREACH key IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(request_value->>key),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty scope rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['run_version','effect_version','lease_seconds'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'number' OR (request_value->>key)!~'^[1-9][0-9]{0,5}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty version rejected';END IF;
 END LOOP;
 o:=request_value->>'organization_id';w:=request_value->>'workspace_id';e:=request_value->>'environment_id';r:=request_value->>'run_id';s:=request_value->>'step_id';worker:=request_value->>'worker_id';token:=request_value->>'lease_token';
 IF NOT COALESCE(request_value->>'operation'='uncertain' AND request_value->'payload'='{}'::jsonb AND jsonb_typeof(request_value->'worker_id')='string' AND worker~'^[a-z][a-z0-9.-]{2,127}$' AND jsonb_typeof(request_value->'lease_token')='string' AND token~'^[a-f0-9]{32}$'
  AND (request_value->>'run_version')::bigint<=999998 AND (request_value->>'effect_version')::bigint<=999998 AND (request_value->>'lease_seconds')::integer BETWEEN 30 AND 300,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty operation rejected';END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_test_uncertain',r||chr(31)||s);
 SELECT x.* INTO prior FROM public.zasp_security_agent_audit x WHERE x.organization_id=o AND x.audit_id=uncertainty_body.audit_id FOR SHARE;
 IF prior.audit_id IS NULL THEN PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);ELSE PERFORM zasp_sa_multistep_prior.test_uncertain_current(o,w,e,r,s);END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
 SELECT * INTO link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id) FOR UPDATE NOWAIT;
 target_value:=public.zasp_production_security_agent_existing_tests_invocation_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,state)=(o,w,e,child.run_id,'started'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id) AND (target_resolution IS DISTINCT FROM target_value OR input_digest IS DISTINCT FROM child.input_digest OR attempt<>child.attempt OR lease_digest IS DISTINCT FROM digest(convert_to(token,'UTF8'),'sha256')))
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered uncertainty journal changed';END IF;
 snapshot_value:=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)),NULL);
 IF prior.audit_id IS NOT NULL THEN
  result_value:=prior.body->'response';deadline:=(prior.body->>'lease_expires_at')::timestamptz;
  IF prior.body->'request' IS DISTINCT FROM request_value-'lease_token' OR prior.body->>'lease_digest' IS DISTINCT FROM encode(digest(convert_to(token,'UTF8'),'sha256'),'hex') OR prior.body->'snapshot' IS DISTINCT FROM snapshot_value
   OR rr.state<>'needs_human' OR rr.version<>(result_value->>'run_version')::bigint OR st.state<>'inconclusive' OR st.version<>(result_value->>'step_version')::bigint OR fx.state<>'unknown_outcome' OR fx.version<>(result_value->>'effect_version')::bigint OR child.state<>'failed' OR child.error_code IS DISTINCT FROM 'outcome_unknown'
   OR fx.outcome_id IS NOT NULL OR fx.result_digest IS NOT NULL OR fx.lease_owner IS NOT NULL OR fx.lease_token IS NOT NULL OR fx.lease_expires_at IS NOT NULL
   OR link.reconcile_state<>'pending' OR link.reconcile_version<>1 OR link.reconcile_worker IS NOT NULL OR link.reconcile_token IS NOT NULL OR link.reconcile_expires_at IS NOT NULL OR link.reconcile_settlement IS NOT NULL
   OR prior.event_digest IS DISTINCT FROM digest(convert_to(prior.body::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered uncertainty replay changed';END IF;
 ELSE
  deadline:=zasp_sa_multistep_prior.test_invocation_lease(o,w,e,child.run_id,convert_to(token,'UTF8'));
  IF rr.version<>(request_value->>'run_version')::bigint OR fx.version<>(request_value->>'effect_version')::bigint OR fx.lease_owner IS DISTINCT FROM worker OR child.worker_id IS DISTINCT FROM worker OR st.state<>'executing' OR st.version<>4 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered uncertainty lease changed';END IF;
  result_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'test_run_id',child.run_id,'attempt',child.attempt,'run_version',rr.version+1,'step_version',st.version+1,'effect_version',fx.version+1,'run_state','needs_human','step_state','inconclusive','effect_state','unknown_outcome','receipt_created',false,'reason','test_outcome_unknown');
  body_value:=jsonb_build_object('request',request_value-'lease_token','lease_digest',encode(digest(convert_to(token,'UTF8'),'sha256'),'hex'),'lease_expires_at',deadline,'snapshot',snapshot_value,'response',result_value);
  IF octet_length(result_value::text)>4096 OR octet_length(body_value::text)>131072 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty bound rejected';END IF;
  UPDATE public.zasp_red_team_runs SET state='failed',version=version+1,error_code='outcome_unknown',completed_at=clock_timestamp(),updated_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child.run_id);
  UPDATE public.zasp_security_agent_effects SET state='unknown_outcome',version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
  UPDATE public.zasp_security_agent_steps SET state='inconclusive',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  UPDATE public.zasp_security_agent_runs SET state='needs_human',version=version+1,last_error_code='test_outcome_unknown',completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  snapshot_value:=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)),NULL);
  body_value:=body_value||jsonb_build_object('snapshot',snapshot_value);
  IF snapshot_value IS NULL OR octet_length(body_value::text)>131072 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered uncertainty snapshot rejected';END IF;
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_test_uncertain',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 END IF;
 PERFORM zasp_sa_multistep_prior.test_uncertain_current(o,w,e,r,s);
 IF deadline<=clock_timestamp() OR NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered uncertainty expired';END IF;
 RETURN result_value;
END $uncertain$;

-- A crashed invocation worker cannot recover any retained journal attempt.
-- A separate security-agent principal may close that exact expired attempt,
-- but has no authority to send provider I/O or manufacture a terminal receipt.
CREATE FUNCTION zasp_sa_multistep_prior.test_reconcile_uncertain(checksum_value text,fingerprint_value text,request_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $reconcile$
<<expiry_body>>
DECLARE o text;w text;e text;r text;s text;worker text;key text;audit_id text;journal_state text;reason_value text;result_value jsonb;snapshot_value jsonb;body_value jsonb;target_value jsonb;item jsonb;lease_value jsonb;
 rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;prior public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered expiry requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered expiry principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered expiry release unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(request_value,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','worker_id','run_version','effect_version']) OR octet_length(request_value::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry request rejected';END IF;
 FOREACH key IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(request_value->>key),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry scope rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['run_version','effect_version'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'number' OR NOT COALESCE(request_value->>key~'^[1-9][0-9]{0,5}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry version rejected';END IF;
 END LOOP;
 o:=request_value->>'organization_id';w:=request_value->>'workspace_id';e:=request_value->>'environment_id';r:=request_value->>'run_id';s:=request_value->>'step_id';worker:=request_value->>'worker_id';
 IF NOT COALESCE(request_value->>'operation'='reconcile_uncertain' AND jsonb_typeof(request_value->'worker_id')='string' AND worker~'^[a-z][a-z0-9.-]{2,127}$'
  AND (request_value->>'run_version')::bigint<=999998 AND (request_value->>'effect_version')::bigint<=999998,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry operation rejected';END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,r);
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_test_expired',r||chr(31)||s);
 SELECT x.* INTO prior FROM public.zasp_security_agent_audit x WHERE x.organization_id=o AND x.audit_id=expiry_body.audit_id FOR SHARE;
 IF prior.audit_id IS NULL THEN PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);ELSE PERFORM zasp_sa_multistep_prior.test_uncertain_current(o,w,e,r,s);END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
 SELECT * INTO link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id) FOR UPDATE NOWAIT;
 SELECT plan->'steps'->1 INTO item FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF child.run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_run',r||chr(31)||s||chr(31)||'run_test')
  OR link.input_digest IS DISTINCT FROM st.input_digest OR fx.input_digest IS DISTINCT FROM st.input_digest OR link.action_key IS DISTINCT FROM 'run_test'
  OR link.test_definition_id IS DISTINCT FROM item->>'target_id' OR link.test_definition_version IS DISTINCT FROM (item->>'test_definition_version')::bigint
  OR link.target_id IS DISTINCT FROM item->>'test_target_id' OR link.target_kind IS DISTINCT FROM item->>'test_target_kind'
  OR child.definition_id IS DISTINCT FROM link.test_definition_id OR child.definition_version IS DISTINCT FROM link.test_definition_version OR child.cancel_requested
  OR link.reconcile_state IS DISTINCT FROM 'pending' OR link.reconcile_version IS DISTINCT FROM 1 OR link.reconcile_worker IS NOT NULL OR link.reconcile_token IS NOT NULL OR link.reconcile_expires_at IS NOT NULL OR link.reconcile_settlement IS NOT NULL
  OR NOT EXISTS(SELECT 1 FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,target_id,target_kind,categories,enabled)=(o,w,e,link.test_definition_id,link.test_definition_version,link.target_id,link.target_kind,link.test_categories,true))
  OR NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(o,w,e,r,s,child.run_id))
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expiry association changed';END IF;
 target_value:=zasp_sa_multistep_prior.test_expiry_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id)
   AND (target_resolution IS DISTINCT FROM target_value OR input_digest IS DISTINCT FROM child.input_digest OR attempt IS DISTINCT FROM child.attempt OR NOT link.test_categories ? category)) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expiry journal changed';END IF;
 SELECT CASE WHEN bool_or(state='started') THEN 'started' ELSE 'completed_unsettled' END INTO journal_state
  FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id);
 reason_value:=CASE journal_state WHEN 'started' THEN 'test_outcome_unknown' ELSE 'test_evidence_unsettled' END;
 IF prior.audit_id IS NOT NULL THEN
  result_value:=prior.body->'response';
  snapshot_value:=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)),NULL);
  IF prior.actor_id IS DISTINCT FROM worker OR prior.event_kind IS DISTINCT FROM 'ordered_test_expired' OR prior.body->'request' IS DISTINCT FROM request_value OR prior.body->'snapshot' IS DISTINCT FROM snapshot_value
   OR result_value->>'journal_state' IS DISTINCT FROM journal_state OR result_value->>'reason' IS DISTINCT FROM reason_value
   OR rr.state IS DISTINCT FROM 'needs_human' OR rr.version IS DISTINCT FROM (result_value->>'run_version')::bigint OR st.state IS DISTINCT FROM 'inconclusive' OR st.version IS DISTINCT FROM (result_value->>'step_version')::bigint
   OR fx.state IS DISTINCT FROM 'unknown_outcome' OR fx.version IS DISTINCT FROM (result_value->>'effect_version')::bigint OR fx.outcome_id IS NOT NULL OR fx.result_digest IS NOT NULL OR fx.lease_owner IS NOT NULL OR fx.lease_token IS NOT NULL OR fx.lease_expires_at IS NOT NULL
   OR child.state IS DISTINCT FROM 'failed' OR child.error_code IS DISTINCT FROM 'outcome_unknown' OR prior.event_digest IS DISTINCT FROM digest(convert_to(prior.body::text,'UTF8'),'sha256') THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expiry replay changed';END IF;
 ELSE
  IF rr.version IS DISTINCT FROM (request_value->>'run_version')::bigint OR fx.version IS DISTINCT FROM (request_value->>'effect_version')::bigint OR st.state IS DISTINCT FROM 'executing' OR st.version IS DISTINCT FROM 4
   OR fx.state IS DISTINCT FROM 'leased' OR child.state IS DISTINCT FROM 'leased' OR fx.attempt IS DISTINCT FROM child.attempt OR fx.attempt NOT BETWEEN 1 AND 5
   OR fx.outcome_id IS NOT NULL OR fx.result_digest IS NOT NULL OR fx.lease_owner IS NULL OR fx.lease_token IS NULL OR fx.lease_expires_at IS NULL OR fx.lease_expires_at>clock_timestamp()
   OR child.worker_id IS DISTINCT FROM fx.lease_owner OR child.lease_token IS DISTINCT FROM convert_to(fx.lease_token,'UTF8') OR child.lease_expires_at IS NULL OR child.lease_expires_at>clock_timestamp()
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child.run_id) AND lease_digest IS DISTINCT FROM digest(convert_to(fx.lease_token,'UTF8'),'sha256')) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expiry is not due';END IF;
  lease_value:=jsonb_build_object('worker_id',fx.lease_owner,'lease_digest',encode(digest(convert_to(fx.lease_token,'UTF8'),'sha256'),'hex'),'effect_expires_at',fx.lease_expires_at,'child_expires_at',child.lease_expires_at,'child_version',child.version,'attempt',fx.attempt);
  result_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'test_run_id',child.run_id,'operation','reconcile_uncertain','attempt',child.attempt,'run_version',rr.version+1,'step_version',st.version+1,'effect_version',fx.version+1,'run_state','needs_human','step_state','inconclusive','effect_state','unknown_outcome','receipt_created',false,'journal_state',journal_state,'reason',reason_value);
  IF octet_length(result_value::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry response rejected';END IF;
  UPDATE public.zasp_red_team_runs SET state='failed',version=version+1,error_code='outcome_unknown',completed_at=clock_timestamp(),updated_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child.run_id);
  UPDATE public.zasp_security_agent_effects SET state='unknown_outcome',version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'run_test');
  UPDATE public.zasp_security_agent_steps SET state='inconclusive',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  UPDATE public.zasp_security_agent_runs SET state='needs_human',version=version+1,last_error_code=reason_value,completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  snapshot_value:=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,s,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)),NULL);
  body_value:=jsonb_build_object('request',request_value,'expired_lease',lease_value,'snapshot',snapshot_value,'response',result_value);
  IF snapshot_value IS NULL OR octet_length(body_value::text)>131072 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered expiry snapshot rejected';END IF;
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_test_expired',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 END IF;
 PERFORM zasp_sa_multistep_prior.test_uncertain_current(o,w,e,r,s);
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expiry authority changed';END IF;
 RETURN result_value;
END $reconcile$;

DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname IN('test_terminal_current','test_settled_current','test_uncertain_current','test_finish_core','test_validate_output','test_snapshot','test_settle','test_uncertain','test_reconcile_uncertain','test_expiry_target') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_red_team_worker,zasp_red_team_adapter',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.test_settle(text,text,text,text,text,text,text,text,text,bigint,bigint,jsonb,bytea,jsonb,bytea) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.test_uncertain(text,text,jsonb) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.test_reconcile_uncertain(text,text,jsonb) TO zasp_security_agent_worker;
