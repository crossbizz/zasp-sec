-- Workload-bound action decisions. Each authenticated token has its own action
-- namespace even when two tokens have the same owner and Environment.
CREATE TABLE IF NOT EXISTS public.zasp_workload_actions (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 credential_id text NOT NULL, action_id text NOT NULL, principal_id text NOT NULL,
 request jsonb NOT NULL, receipt jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 outcome jsonb, observed_at timestamptz,
 PRIMARY KEY (organization_id,workspace_id,environment_id,credential_id,action_id),
 CHECK ((outcome IS NULL) = (observed_at IS NULL))
);
ALTER TABLE public.zasp_workload_actions OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_workload_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_workload_actions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_workload_actions FROM PUBLIC;
DO $action_policy$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_workload_actions' AND policyname='workload_action_authority') THEN
  CREATE POLICY workload_action_authority ON public.zasp_workload_actions TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $action_policy$;

-- The read and commit share a versioned snapshot. Check the snapshot again
-- on commit so that evaluation against a superseded policy cannot be admitted.
CREATE OR REPLACE FUNCTION zasp_authorization80.workload_policy_snapshot(o text,w text,e text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $snapshot$
DECLARE policies jsonb;
BEGIN
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',id,'version',version,'body',body-'_target_environment_id') ORDER BY id COLLATE "C"),'[]'::jsonb)
 INTO policies FROM (SELECT id,version,body FROM public.zasp_workflow_records
   WHERE (organization_id,workspace_id,environment_id,kind)=(o,w,e,'policy') AND deleted_at IS NULL
    AND body->>'trigger'='tool' AND body->>'rollout' IN ('monitor','enforced')
   ORDER BY id COLLATE "C" LIMIT 65) AS active;
 IF jsonb_array_length(policies)>64 OR octet_length(policies::text)>262144 THEN
  RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='action policy capacity exceeded'; END IF;
 RETURN jsonb_build_object('policies',policies,'revision','sha256:'||encode(public.digest(convert_to(policies::text,'UTF8'),'sha256'),'hex'));
END $snapshot$;
ALTER FUNCTION zasp_authorization80.workload_policy_snapshot(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_policy_snapshot(text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_action(o text,w text,e text,actor text,q jsonb,decision jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $workload_action$
DECLARE p jsonb; binding text; snapshot jsonb; active_runs text[]; prior public.zasp_workload_actions%ROWTYPE; a text:=q->>'action_id';
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,actor,'createWorkloadActionDecision','decide_actions','environment',e,false,false,false,true);
 binding:=p->>'credential_id';
 IF p->>'credential_kind' IS DISTINCT FROM '2' OR binding IS NULL OR NOT COALESCE(p->'pat_ceiling' ? 'decide_actions',false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload binding required'; END IF;
 IF NOT COALESCE(jsonb_typeof(q)='object' AND (q-ARRAY['schema_version','action_id','source_session_ref','source_call_ref','action_kind','operation','resource'])='{}'::jsonb
  AND q->>'schema_version'='action.v1' AND q->>'action_kind'='tool_call' AND a~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  AND q->>'operation'~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' AND jsonb_typeof(q->'resource')='object'
  AND ((q->'resource')-ARRAY['kind','classification'])='{}'::jsonb
  AND q#>>'{resource,kind}'~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' AND q#>>'{resource,classification}'~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  AND (NOT q?'source_session_ref' OR q->>'source_session_ref'~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$')
  AND (NOT q?'source_call_ref' OR q->>'source_call_ref'~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workload action'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,binding,a),0));
 SELECT * INTO prior FROM public.zasp_workload_actions
 WHERE (organization_id,workspace_id,environment_id,credential_id,action_id)=(o,w,e,binding,a);
 IF FOUND THEN
  IF prior.request<>q THEN RETURN '{"error":"action_id_conflict"}'::jsonb; END IF;
  PERFORM zasp_authorization80.product_settled(p); RETURN jsonb_build_object('receipt',prior.receipt);
 END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(concat_ws(chr(31),'workload-controls',o,w,e,binding),0));
 SELECT coalesce(array_agg(x.run_id ORDER BY x.run_id),'{}'::text[]) INTO active_runs FROM public.zasp_workload_containments x
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.credential_id)=(o,w,e,binding)
 AND x.released_at IS NULL AND x.expires_at>clock_timestamp() AND zasp_authorization80.workload_control_end(x)>clock_timestamp();
 snapshot:=zasp_authorization80.workload_policy_snapshot(o,w,e);
 IF cardinality(active_runs)>0 THEN
  snapshot:=snapshot||jsonb_build_object('isolated',true,'revision','sha256:'||encode(public.digest(convert_to((snapshot->>'revision')||array_to_json(active_runs)::text,'UTF8'),'sha256'),'hex'));
 END IF;
 IF decision IS NULL THEN
  snapshot:=snapshot||COALESCE((SELECT jsonb_build_object('bound_agent_id',b.agent_id,'bound_session_id',b.session_id)
   FROM public.zasp_workload_bindings b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(o,w,e,binding)),'{}'::jsonb);
  PERFORM zasp_authorization80.product_settled(p); RETURN snapshot; END IF;
 IF NOT COALESCE(jsonb_typeof(decision)='object' AND (decision-ARRAY['action_id','decision_id','policy_revision_id','mode','verdict','coverage','reason_code','would_block'])='{}'::jsonb
  AND decision->>'action_id'=a AND public.zasp_valid_product_id(decision->>'decision_id')
  AND decision->>'coverage'='pre_action_supported' AND decision->>'mode' IN ('monitor','enforce')
  AND decision->>'verdict' IN ('allow','block') AND (decision->>'mode'<>'monitor' OR decision->>'verdict'='allow')
  AND decision->>'reason_code' IN ('no_matching_restriction','rule_would_block','rule_blocked','supervised_session_isolation')
  AND jsonb_typeof(decision->'would_block')='boolean' AND decision?'policy_revision_id',false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workload decision'; END IF;
 IF decision->>'policy_revision_id' IS DISTINCT FROM snapshot->>'revision' OR (cardinality(active_runs)>0) IS DISTINCT FROM (decision->>'reason_code'='supervised_session_isolation') OR (cardinality(active_runs)>0 AND decision->>'verdict'<>'block') THEN
  RETURN '{"error":"policy_changed"}'::jsonb; END IF;
 INSERT INTO public.zasp_workload_actions(organization_id,workspace_id,environment_id,credential_id,action_id,principal_id,request,receipt,containment_runs)
 VALUES(o,w,e,binding,a,actor,q,decision,active_runs);
 PERFORM zasp_authorization80.product_settled(p); RETURN jsonb_build_object('receipt',decision);
END $workload_action$;
ALTER FUNCTION zasp_authorization80.workload_action(text,text,text,text,jsonb,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_action(text,text,text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_action(text,text,text,text,jsonb,jsonb) TO zasp_discovery_api;

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_outcome(o text,w text,e text,actor text,a text,q jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $workload_outcome$
DECLARE p jsonb; binding text; prior public.zasp_workload_actions%ROWTYPE;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,actor,'recordWorkloadActionOutcome','decide_actions','environment',e,false,false,false,true);
 binding:=p->>'credential_id';
 IF p->>'credential_kind' IS DISTINCT FROM '2' OR binding IS NULL OR NOT COALESCE(p->'pat_ceiling' ? 'decide_actions',false) OR p#>>'{path_parameters,actionId}' IS DISTINCT FROM a THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload binding required'; END IF;
 IF NOT COALESCE(jsonb_typeof(q)='object' AND (q-ARRAY['schema_version','action_id','decision_id','status'])='{}'::jsonb
  AND q->>'schema_version'='action-outcome.v1' AND q->>'action_id'=a AND public.zasp_valid_product_id(q->>'decision_id')
  AND q->>'status' IN('not_dispatched','returned','raised','cancelled'),false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workload outcome'; END IF;
 SELECT * INTO prior FROM public.zasp_workload_actions WHERE(organization_id,workspace_id,environment_id,credential_id,action_id)=(o,w,e,binding,a) FOR UPDATE;
 IF NOT FOUND OR prior.receipt->>'decision_id' IS DISTINCT FROM q->>'decision_id' THEN RETURN '{"error":"unknown_action"}'::jsonb; END IF;
 IF prior.outcome IS NOT NULL AND prior.outcome<>q THEN RETURN '{"error":"action_outcome_conflict"}'::jsonb; END IF;
 IF prior.outcome IS NULL THEN
  UPDATE public.zasp_workload_actions SET outcome=q,observed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,credential_id,action_id)=(o,w,e,binding,a); END IF;
 PERFORM zasp_authorization80.product_settled(p); RETURN '{"recorded":true}'::jsonb;
END $workload_outcome$;
ALTER FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_outcome(text,text,text,text,text,jsonb) TO zasp_discovery_api;

-- WS12. Findings-only add-on registry. All reads and mutations are admitted by
-- the current Environment proof. Received evidence stays reported until an
-- independent attestation mechanism exists. No paths or raw file data enter.
CREATE TABLE IF NOT EXISTS public.zasp_addon_versions (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 id text NOT NULL CHECK(public.zasp_valid_product_id(id)), manifest_digest text NOT NULL CHECK(manifest_digest ~ '^sha256:[a-f0-9]{64}$'),
 origin text NOT NULL CHECK(origin IN('ci','local','private_worker')), origin_credential text NOT NULL, ruleset text NOT NULL,
 findings jsonb NOT NULL, review_state text NOT NULL DEFAULT 'pending' CHECK(review_state IN('pending','approved','rejected','revoked')),
 revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0), created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,id),
 UNIQUE(organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset)
);
CREATE TABLE IF NOT EXISTS public.zasp_addon_scan_receipts (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 credential_id text NOT NULL, request_key text NOT NULL, actor text NOT NULL,
 scan_id text NOT NULL CHECK(public.zasp_valid_product_id(scan_id)), report jsonb NOT NULL,
 receipt jsonb NOT NULL, received_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id,request_key), UNIQUE(organization_id,workspace_id,environment_id,scan_id)
);
CREATE TABLE IF NOT EXISTS public.zasp_addon_review_history (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 actor text NOT NULL, request_key text NOT NULL, version_id text NOT NULL, expected_revision bigint NOT NULL, state text NOT NULL,
 receipt jsonb NOT NULL, reviewed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor,request_key), UNIQUE(organization_id,workspace_id,environment_id,version_id,expected_revision),
 FOREIGN KEY(organization_id,workspace_id,environment_id,version_id) REFERENCES public.zasp_addon_versions(organization_id,workspace_id,environment_id,id)
);
DO $addon_tables$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['zasp_addon_versions','zasp_addon_scan_receipts','zasp_addon_review_history'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',name);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',name);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=name AND policyname=name||'_authority') THEN
   EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true)',name||'_authority',name);
  END IF;
 END LOOP;
END $addon_tables$;

DO $v2_token_permissions$
DECLARE f record; d text; anchor CONSTANT text := $a$NOT IN('use_gateway','view',$a$;
 replacement CONSTANT text := $b$NOT IN('submit_addon_scans','decide_actions','sync_endpoint','use_gateway','view',$b$; applied boolean:=false;
BEGIN
 FOR f IN SELECT p.oid FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_identity'::regnamespace AND p.proname='create_pat' LOOP
  d:=pg_get_functiondef(f.oid);
  IF position(replacement IN d)>0 THEN applied:=true;
  ELSIF length(d)-length(replace(d,anchor,''))=length(anchor) THEN EXECUTE replace(d,anchor,replacement); applied:=true; END IF;
 END LOOP;
 IF NOT applied THEN RAISE EXCEPTION 'unrecognized API token permission list'; END IF;
END $v2_token_permissions$;

CREATE OR REPLACE FUNCTION zasp_authorization80.addon_report_valid(report jsonb,e text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $addon_valid$
DECLARE item jsonb; seen text[]:=ARRAY[]::text[]; upload jsonb;
BEGIN
 -- Strip only the closed upload evidence and validate the ordinary findings
 -- envelope with the same rule catalog. Admission of this origin requires
 -- the registered machine credential and grant checks in addon_scan_submit.
 IF report->>'origin'='private_worker' THEN
  upload:=report->'private_upload';
  IF jsonb_typeof(upload) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
  IF NOT COALESCE((SELECT count(*) FROM jsonb_object_keys(upload))=3 AND upload ?& ARRAY['id','archive_digest','archive_bytes']
   AND public.zasp_valid_product_id(upload->>'id') AND (upload->>'archive_digest')~'^sha256:[0-9a-f]{64}$'
   AND jsonb_typeof(upload->'archive_bytes')='number' AND (upload->>'archive_bytes')~'^[1-9][0-9]{0,6}$',false) THEN RETURN false; END IF;
  IF (upload->>'archive_bytes')::bigint>8388608 THEN RETURN false; END IF;
  report:=(report-'private_upload')||'{"origin":"local"}'::jsonb;
 END IF;
 IF jsonb_typeof(report) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(report))<>9
  OR NOT report ?& ARRAY['schema_version','environment_id','manifest_method','ruleset','completeness','manifest_digest','origin','findings','skipped_count']
  OR report->>'environment_id' IS DISTINCT FROM e OR report->>'schema_version' IS DISTINCT FROM 'zasp-addon-findings.v1'
  OR report->>'manifest_method' IS DISTINCT FROM 'addon-manifest.v1' OR report->>'ruleset' IS DISTINCT FROM 'zasp-static.v1'
  OR NOT COALESCE(report->>'origin' IN('ci','local') AND report->>'completeness' IN('complete','partial'),false)
  OR jsonb_typeof(report->'skipped_count') IS DISTINCT FROM 'number' OR report->>'skipped_count' !~ '^(0|[1-9][0-9]{0,5}|1000000)$'
  OR jsonb_typeof(report->'findings') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF report->>'completeness'='complete' AND (NOT COALESCE(report->>'manifest_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR report->>'skipped_count'<>'0')
  OR report->>'completeness'='partial' AND report->'manifest_digest' IS DISTINCT FROM 'null'::jsonb OR jsonb_array_length(report->'findings')>6 THEN RETURN false; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(report->'findings') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT item ?& ARRAY['rule_id','count'] OR (SELECT count(*) FROM jsonb_object_keys(item))<>2
   OR NOT COALESCE(item->>'rule_id' IN('dependency.unpinned','script.shell_execution','script.network_access','instruction.hidden_text','mcp.unpinned_launcher','mcp.remote_endpoint'),false)
   OR (item->>'rule_id')=ANY(seen) OR jsonb_typeof(item->'count') IS DISTINCT FROM 'number' OR item->>'count' !~ '^([1-9][0-9]{0,5}|1000000)$' THEN RETURN false; END IF;
  seen:=array_append(seen,item->>'rule_id');
 END LOOP;
 RETURN true;
END $addon_valid$;

CREATE OR REPLACE FUNCTION zasp_authorization80.addon_scan_submit(o text,w text,e text,actor_value text,key_value text,scan_value text,version_candidate text,report_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_submit$
DECLARE proof jsonb; credential text; version_value text; receipt_value jsonb; prior public.zasp_addon_scan_receipts%ROWTYPE;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor_value,'submitAddonScan','submit_addon_scans','environment',e,false,false,false,true);
 credential:=proof->>'credential_id';
 IF proof->>'credential_kind' IS DISTINCT FROM '2' OR proof->'pat_ceiling' IS DISTINCT FROM '["submit_addon_scans"]'::jsonb OR credential IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='restricted submission credential required'; END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(scan_value) AND public.zasp_valid_product_id(version_candidate) AND key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND zasp_authorization80.addon_report_valid(report_value,e),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid findings report'; END IF;
 -- Serialize only this scoped retry key. Concurrent distinct scans can share a version.
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,credential,key_value)::text,0));
 SELECT * INTO prior FROM public.zasp_addon_scan_receipts WHERE (organization_id,workspace_id,environment_id,credential_id,request_key)=(o,w,e,credential,key_value);
 IF FOUND THEN IF prior.report=report_value THEN RETURN prior.receipt; END IF; RETURN '"conflict"'::jsonb; END IF;
 IF report_value->>'origin'='private_worker' AND NOT EXISTS(
  SELECT 1 FROM public.zasp_private_addon_uploads g JOIN public.zasp_private_addon_reporters b ON b.grant_id=g.grant_id
  WHERE (g.organization_id,g.workspace_id,g.environment_id,g.grant_id)=(o,w,e,report_value#>>'{private_upload,id}')
   AND b.credential_id=credential AND key_value='private-upload-'||g.grant_id
   AND (g.archive_digest,g.archive_bytes)=(report_value#>>'{private_upload,archive_digest}',(report_value#>>'{private_upload,archive_bytes}')::bigint)
   AND g.expires_at+interval '1 hour'>clock_timestamp()
 ) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='registered upload worker required'; END IF;
 IF report_value->>'completeness'='complete' THEN
  INSERT INTO public.zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings) VALUES(o,w,e,version_candidate,report_value->>'manifest_digest',report_value->>'origin',credential,report_value->>'ruleset',report_value->'findings') ON CONFLICT(organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset) DO NOTHING;
  SELECT id INTO STRICT version_value FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset)=(o,w,e,report_value->>'manifest_digest',report_value->>'origin',credential,report_value->>'ruleset');
 END IF;
 receipt_value:=jsonb_build_object('scan_id',scan_value,'version_id',version_value,'manifest_digest',report_value->'manifest_digest','completeness',report_value->>'completeness','review_path','/inventory/tools?addon='||version_value);
 INSERT INTO public.zasp_addon_scan_receipts(organization_id,workspace_id,environment_id,credential_id,request_key,actor,scan_id,report,receipt) VALUES(o,w,e,credential,key_value,actor_value,scan_value,report_value,receipt_value);
 PERFORM zasp_authorization80.product_settled(proof); RETURN receipt_value;
END $addon_submit$;

CREATE OR REPLACE FUNCTION zasp_authorization80.addon_version_value(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $addon_value$
 SELECT jsonb_build_object('id',id,'manifest_digest',manifest_digest,'origin',origin,'provenance','reported','ruleset',ruleset,'findings',findings,'review_state',review_state,'revision',revision)
 FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i)
$addon_value$;
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_version_get(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_get$
DECLARE proof jsonb;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,NULL,'getAddonVersion','view','environment',e,false,true,false,false);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong add-on scope'; END IF;
 RETURN COALESCE(zasp_authorization80.addon_version_value(o,w,e,i),'null'::jsonb);
END $addon_get$;
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_version_review(o text,w text,e text,actor_value text,i text,key_value text,expected_version bigint,state_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_review$
DECLARE proof jsonb; revision_value bigint; receipt_value jsonb; prior public.zasp_addon_review_history%ROWTYPE;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor_value,'reviewAddonVersion','manage_workflows','environment',e,false,true,true,true);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong add-on scope'; END IF;
 IF NOT COALESCE(key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND expected_version>=0 AND state_value IN('approved','rejected','revoked'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid add-on review'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,actor_value,key_value)::text,1));
 SELECT * INTO prior FROM public.zasp_addon_review_history WHERE (organization_id,workspace_id,environment_id,actor,request_key)=(o,w,e,actor_value,key_value);
 IF FOUND THEN IF (prior.version_id,prior.expected_revision,prior.state)=(i,expected_version,state_value) THEN RETURN prior.receipt; END IF; RETURN '"conflict"'::jsonb; END IF;
 SELECT revision INTO revision_value FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 IF revision_value<>expected_version THEN RETURN '"conflict"'::jsonb; END IF;
 UPDATE public.zasp_addon_versions SET review_state=state_value,revision=revision+1 WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i);
 receipt_value:=zasp_authorization80.addon_version_value(o,w,e,i);
 INSERT INTO public.zasp_addon_review_history(organization_id,workspace_id,environment_id,actor,request_key,version_id,expected_revision,state,receipt) VALUES(o,w,e,actor_value,key_value,i,expected_version,state_value,receipt_value);
 PERFORM zasp_authorization80.product_settled(proof); RETURN receipt_value;
END $addon_review$;
CREATE INDEX IF NOT EXISTS zasp_addon_versions_recent_idx ON public.zasp_addon_versions(organization_id,workspace_id,environment_id,created_at DESC,id DESC);
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_versions_list(o text,w text,e text,n integer,after_id text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_list$
DECLARE anchor_time timestamptz; result jsonb;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'listAddonVersions','view','environment',e,false,true,false,false);
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR (after_id IS NOT NULL AND NOT public.zasp_valid_product_id(after_id)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid page'; END IF;
 IF after_id IS NOT NULL THEN
  SELECT created_at INTO anchor_time FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,after_id);
  IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 END IF;
 WITH candidates AS MATERIALIZED (
  SELECT id,created_at FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id)=(o,w,e)
   AND (after_id IS NULL OR (created_at,id)<(anchor_time,after_id)) ORDER BY created_at DESC,id DESC LIMIT n+1
 ), page AS (SELECT * FROM candidates ORDER BY created_at DESC,id DESC LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(zasp_authorization80.addon_version_value(o,w,e,id) ORDER BY created_at DESC,id DESC) FROM page),'[]'::jsonb),
  'next_cursor',CASE WHEN (SELECT count(*) FROM candidates)>n THEN (SELECT id FROM page ORDER BY created_at,id LIMIT 1) END) INTO result;
 RETURN result;
END $addon_list$;

DO $addon_grants$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM (VALUES
 ('zasp_authorization80.addon_versions_list(text,text,text,integer,text)',true),('zasp_authorization80.addon_report_valid(jsonb,text)',false),('zasp_authorization80.addon_version_value(text,text,text,text)',false),
 ('zasp_authorization80.addon_scan_submit(text,text,text,text,text,text,text,jsonb)',true),('zasp_authorization80.addon_version_get(text,text,text,text)',true),('zasp_authorization80.addon_version_review(text,text,text,text,text,text,bigint,text)',true)
 ) v(signature,api) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.api THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f.signature::regprocedure); END IF;
 END LOOP;
END $addon_grants$;


-- Managed endpoint pilot. Browser operations use the existing Environment proof.
-- Device transport credentials are exclusive and additionally require Ed25519
-- operation/body proofs in the API. Both the preflight and write rebind to
-- the same active key, generation, PAT and scoped device row.
CREATE TABLE IF NOT EXISTS public.zasp_endpoint_devices (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 id text NOT NULL CHECK(public.zasp_valid_product_id(id)), credential_id text NOT NULL CHECK(public.zasp_valid_product_id(credential_id)),
 device_key text NOT NULL, policy_key text NOT NULL, cohort text NOT NULL, generation bigint NOT NULL DEFAULT 1,
 version bigint NOT NULL DEFAULT 1, state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','active','retired')),
 policy_bundle jsonb, policy_revision bigint NOT NULL DEFAULT 0, policy_generation bigint,
 reported jsonb, last_seen timestamptz, enrolled_at timestamptz, retired_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,id), UNIQUE(organization_id,workspace_id,environment_id,credential_id)
);
ALTER TABLE public.zasp_endpoint_devices ADD COLUMN IF NOT EXISTS policy_expires_at timestamptz, ADD COLUMN IF NOT EXISTS reported_at timestamptz;
CREATE TABLE IF NOT EXISTS public.zasp_endpoint_admin_receipts (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL, actor text NOT NULL,request_key text NOT NULL,
 operation text NOT NULL,id text NOT NULL,expected bigint NOT NULL,input jsonb NOT NULL,receipt jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor,request_key)
);
CREATE TABLE IF NOT EXISTS public.zasp_endpoint_deliveries (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,generation bigint NOT NULL,
 nonce text NOT NULL,operation text NOT NULL,digest text NOT NULL,receipt jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,generation,nonce)
);
CREATE TABLE IF NOT EXISTS public.zasp_endpoint_partitions (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,partition_id text NOT NULL,
 generation bigint NOT NULL, observed jsonb NOT NULL, complete_snapshot jsonb,
 PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,partition_id)
);
ALTER TABLE public.zasp_endpoint_partitions ADD COLUMN IF NOT EXISTS observed_at timestamptz, ADD COLUMN IF NOT EXISTS complete_at timestamptz;
CREATE TABLE IF NOT EXISTS public.zasp_endpoint_observations (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,device_id text NOT NULL,
 credential_generation bigint NOT NULL,action_id text NOT NULL,observation jsonb NOT NULL,received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,device_id,credential_generation,action_id)
);
DO $fleet_tables$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['zasp_endpoint_devices','zasp_endpoint_admin_receipts','zasp_endpoint_deliveries','zasp_endpoint_partitions','zasp_endpoint_observations'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',t);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',t);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='endpoint_authority') THEN
   EXECUTE format('CREATE POLICY endpoint_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $fleet_tables$;

CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_view(d public.zasp_endpoint_devices) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $ep_view$
 SELECT jsonb_build_object('id',d.id,'cohort',d.cohort,'state',d.state,'version',d.version,'credential_generation',d.generation,
 'last_seen',d.last_seen,'connection',CASE WHEN d.state='retired' THEN 'retired' WHEN d.last_seen IS NULL THEN 'never_seen' WHEN d.last_seen>=statement_timestamp()-interval '15 minutes' THEN 'online' ELSE 'stale' END,
 'policy_revision',d.policy_revision,'reported_policy_revision',COALESCE((d.reported->>'policy_revision')::bigint,0),
 'acknowledged',COALESCE(d.state='active' AND d.reported_at>=statement_timestamp()-interval '15 minutes' AND d.policy_revision>0
   AND d.policy_generation=d.generation AND d.policy_expires_at>statement_timestamp() AND d.reported->>'policy_status'='verified_cache' AND (d.reported->>'policy_revision')::bigint=d.policy_revision,false),
 'queued_receipts',d.reported->'queued_receipts','dropped_receipts',d.reported->'dropped_receipts')
$ep_view$;
ALTER FUNCTION zasp_authorization80.endpoint_view(public.zasp_endpoint_devices) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.endpoint_view(public.zasp_endpoint_devices) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_admin(o text,w text,e text,a text,op text,target_id text,idem text,expect bigint,q jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ep_admin$
DECLARE p jsonb; edit boolean; d public.zasp_endpoint_devices%ROWTYPE; prior public.zasp_endpoint_admin_receipts%ROWTYPE; reply jsonb; items jsonb; lim integer; more text;
BEGIN
 IF op NOT IN ('registerEndpointDevice','listEndpointDevices','getEndpointDevice','rotateEndpointCredential','retireEndpointDevice','publishEndpointPolicy') OR op IS NULL THEN RAISE insufficient_privilege; END IF;
 edit:=op NOT IN('listEndpointDevices','getEndpointDevice');
 p:=zasp_authorization80.product_request(o,w,e,a,op,CASE WHEN edit THEN 'manage_workflows' ELSE 'view' END,'environment',e,false,true,edit,edit);
 IF (op NOT IN ('registerEndpointDevice','listEndpointDevices') AND p#>>'{path_parameters,id}' IS DISTINCT FROM target_id)
 OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR octet_length(q::text)>8192 THEN RAISE insufficient_privilege; END IF;
 IF op='listEndpointDevices' THEN
  lim:=(q->>'limit')::integer;
  IF lim IS NULL OR lim NOT BETWEEN 1 AND 100 OR (q->>'after'<>'' AND NOT public.zasp_valid_product_id(q->>'after')) THEN RAISE invalid_parameter_value; END IF;
  WITH page AS (SELECT v AS rowval FROM public.zasp_endpoint_devices v WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND id COLLATE "C"> (q->>'after') COLLATE "C" ORDER BY id COLLATE "C" LIMIT lim+1),
  numbered AS (SELECT rowval,row_number() OVER(ORDER BY (rowval).id COLLATE "C") n FROM page)
  SELECT COALESCE(jsonb_agg(zasp_authorization80.endpoint_view(rowval) ORDER BY n) FILTER(WHERE n<=lim),'[]'::jsonb),CASE WHEN max(n)>lim THEN max((rowval).id) FILTER(WHERE n=lim) END INTO items,more FROM numbered;
  RETURN jsonb_build_object('items',items,'next_after_id',more,'counts',(SELECT jsonb_build_object('expected',count(*) FILTER(WHERE v.state<>'retired'),
   'enrolled',count(*) FILTER(WHERE v.state='active'),'online',count(*) FILTER(WHERE (zasp_authorization80.endpoint_view(v)->>'connection')='online'),
   'acknowledged',count(*) FILTER(WHERE (zasp_authorization80.endpoint_view(v)->>'acknowledged')::boolean)) FROM public.zasp_endpoint_devices v WHERE (organization_id,workspace_id,environment_id)=(o,w,e)));
 END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(target_id),false) THEN RAISE invalid_parameter_value; END IF;
 IF NOT edit THEN
  SELECT * INTO d FROM public.zasp_endpoint_devices WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id);
  IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
  WITH roots AS (
    SELECT r.* FROM public.zasp_endpoint_partitions r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.device_id)=(o,w,e,target_id)
    ORDER BY r.observed_at DESC NULLS LAST,r.partition_id COLLATE "C" LIMIT 8
  ), receipts AS (
    SELECT r.* FROM public.zasp_endpoint_observations r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.device_id)=(o,w,e,target_id)
    ORDER BY r.received_at DESC,r.credential_generation DESC,r.action_id COLLATE "C" LIMIT 20
  )
  SELECT zasp_authorization80.endpoint_view(d)||jsonb_build_object(
    'reported_adapter',COALESCE(d.reported->>'adapter','unknown'),
    'inventory_partitions',(SELECT count(*) FROM public.zasp_endpoint_partitions WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,target_id)),
    'observation_count',(SELECT count(*) FROM public.zasp_endpoint_observations WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,target_id)),
    'partition_summaries',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'partition_id',r.partition_id,'generation',r.generation,'complete',r.observed->'complete',
      'observed_count',jsonb_array_length(r.observed->'installations'),
      'observed_installations',COALESCE((SELECT jsonb_agg(inst ORDER BY inst->>'installation_id') FROM (SELECT inst FROM jsonb_array_elements(r.observed->'installations') inst ORDER BY inst->>'installation_id' LIMIT 12) x),'[]'::jsonb),
      'last_complete_generation',r.complete_snapshot->'snapshot_generation',
      'confirmed_count',jsonb_array_length(r.complete_snapshot->'installations'),
      'confirmed_installations',COALESCE((SELECT jsonb_agg(inst ORDER BY inst->>'installation_id') FROM (SELECT inst FROM jsonb_array_elements(r.complete_snapshot->'installations') inst ORDER BY inst->>'installation_id' LIMIT 12) x),'[]'::jsonb)
    ) ORDER BY r.observed_at DESC NULLS LAST,r.partition_id COLLATE "C") FROM roots r),'[]'::jsonb),
    'recent_observations',COALESCE((SELECT jsonb_agg(jsonb_build_object(
      'action_id',r.action_id,'session_ref',r.observation->'session_ref','credential_generation',r.credential_generation,
      'observed_at',r.observation->'observed_at','policy_revision',r.observation->'policy_revision',
      'mode',r.observation->'mode','verdict',r.observation->'verdict','would_block',r.observation->'would_block',
      'target_class',r.observation->'target_class','skill_usage',r.observation->'skill_usage','target_effect',r.observation->'target_effect'
     )||COALESCE((SELECT jsonb_build_object('graph_evidence_id',g.evidence_id,'graph_state',CASE WHEN g.projected_at IS NULL THEN 'pending' ELSE 'projected' END)
      FROM public.zasp_action_graph_evidence g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.evidence_id)=(o,w,e,
       public.zasp_discovery_canonical_id(o,w,e,'signed_hook_receipt',concat_ws('/',r.device_id,r.credential_generation,r.action_id)))),'{}'::jsonb)
      ORDER BY r.received_at DESC,r.credential_generation DESC,r.action_id COLLATE "C") FROM receipts r),'[]'::jsonb)
  ) INTO reply;
  RETURN reply;
 END IF;
 IF idem IS NULL OR length(idem) NOT BETWEEN 8 AND 160 OR expect<0 THEN RAISE invalid_parameter_value; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,a,idem),0));
 SELECT * INTO prior FROM public.zasp_endpoint_admin_receipts WHERE (organization_id,workspace_id,environment_id,actor,request_key)=(o,w,e,a,idem);
 IF q='{"inspect":true}'::jsonb AND op='publishEndpointPolicy' THEN
  SELECT * INTO d FROM public.zasp_endpoint_devices WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id);
  IF NOT FOUND OR d.state='retired' THEN RETURN 'null'::jsonb; END IF;
  PERFORM zasp_authorization80.product_settled(p);
  RETURN jsonb_build_object('credential_generation',d.generation,'policy_public_key',d.policy_key);
 END IF;
 IF prior.request_key IS NOT NULL THEN
  IF prior.operation<>op OR prior.expected<>expect OR (op<>'registerEndpointDevice' AND prior.id<>target_id) OR prior.input<>q THEN RETURN '"conflict"'::jsonb; END IF;
  PERFORM zasp_authorization80.product_settled(p);RETURN prior.receipt;
 END IF;
 IF op IN('registerEndpointDevice','rotateEndpointCredential') THEN
  IF NOT COALESCE(public.zasp_valid_product_id(q->>'credential_id') AND q->>'device_public_key' ~ '^[A-Za-z0-9+/]{43}=$',false) THEN RAISE invalid_parameter_value; END IF;
  IF NOT EXISTS(SELECT FROM public.zasp_product_api_tokens tok WHERE (tok.organization_id,tok.workspace_id,tok.environment_id,tok.id)=(o,w,e,q->>'credential_id')
    AND tok.permissions='["sync_endpoint"]'::jsonb AND tok.revoked_at IS NULL AND tok.expires_at>clock_timestamp()) THEN RETURN '"forbidden"'::jsonb; END IF;
 END IF;
 IF op='registerEndpointDevice' THEN
  IF NOT COALESCE(q->>'cohort' ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' AND q->>'policy_public_key' ~ '^[A-Za-z0-9+/]{43}=$' AND q->>'policy_public_key'<>q->>'device_public_key',false) THEN RAISE invalid_parameter_value; END IF;
  INSERT INTO public.zasp_endpoint_devices(organization_id,workspace_id,environment_id,id,credential_id,device_key,policy_key,cohort)
  VALUES(o,w,e,target_id,q->>'credential_id',q->>'device_public_key',q->>'policy_public_key',q->>'cohort') ON CONFLICT DO NOTHING RETURNING * INTO d;
  IF NOT FOUND THEN RETURN '"conflict"'::jsonb; END IF;
 ELSE
  SELECT * INTO d FROM public.zasp_endpoint_devices WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id) FOR UPDATE;
  IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
  IF d.version<>expect OR d.state='retired' THEN RETURN '"conflict"'::jsonb; END IF;
  IF op='publishEndpointPolicy' THEN
   IF NOT COALESCE((q->>'generation')::bigint=d.generation AND (q->>'policy_revision')::bigint>d.policy_revision
     AND (q->>'expires_at')::timestamptz>clock_timestamp() AND (q->>'expires_at')::timestamptz<=clock_timestamp()+interval '24 hours' AND jsonb_typeof(q->'bundle')='object' AND jsonb_typeof(q#>'{bundle,payload}')='string' AND jsonb_typeof(q#>'{bundle,signature}')='string',false) THEN RETURN '"conflict"'::jsonb; END IF;
   UPDATE public.zasp_endpoint_devices SET policy_bundle=q->'bundle',policy_expires_at=(q->>'expires_at')::timestamptz,policy_generation=d.generation,policy_revision=(q->>'policy_revision')::bigint,version=version+1
    WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id) RETURNING * INTO d;
  ELSIF op='rotateEndpointCredential' THEN
   IF d.device_key=q->>'device_public_key' OR d.policy_key=q->>'device_public_key' OR d.credential_id=q->>'credential_id' THEN RETURN '"conflict"'::jsonb; END IF;
   BEGIN
    UPDATE public.zasp_endpoint_devices SET credential_id=q->>'credential_id',device_key=q->>'device_public_key',generation=generation+1,version=version+1,state='pending',
    reported=NULL,reported_at=NULL,last_seen=NULL,policy_generation=NULL,policy_bundle=NULL WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id) RETURNING * INTO d;
   EXCEPTION WHEN unique_violation THEN RETURN '"conflict"'::jsonb; END;
  ELSE
   UPDATE public.zasp_endpoint_devices SET state='retired',retired_at=clock_timestamp(),version=version+1 WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id) RETURNING * INTO d;
  END IF;
 END IF;
 reply:=zasp_authorization80.endpoint_view(d);
 INSERT INTO public.zasp_endpoint_admin_receipts VALUES(o,w,e,a,idem,op,target_id,expect,q,reply,transaction_timestamp());
 PERFORM zasp_authorization80.product_settled(p);RETURN reply;
END $ep_admin$;
ALTER FUNCTION zasp_authorization80.endpoint_admin(text,text,text,text,text,text,text,bigint,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.endpoint_admin(text,text,text,text,text,text,text,bigint,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.endpoint_admin(text,text,text,text,text,text,text,bigint,jsonb) TO zasp_discovery_api;

CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_machine(o text,w text,e text,a text,op text,target_id text,gen bigint,phase text,q jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ep_machine$
DECLARE p jsonb; d public.zasp_endpoint_devices%ROWTYPE; previous public.zasp_endpoint_deliveries%ROWTYPE; part public.zasp_endpoint_partitions%ROWTYPE;
 k text; response_value jsonb:='{"recorded":true}'::jsonb; v jsonb:=q->'input'; rec jsonb; seen jsonb; current_time_unix bigint:=extract(epoch from clock_timestamp())::bigint;
BEGIN
 IF op IS NULL OR op NOT IN('fetchEndpointPolicy','exchangeEndpointEnrollment','recordEndpointHeartbeat','recordEndpointInventory','recordEndpointObservations') THEN RAISE insufficient_privilege; END IF;
 p:=zasp_authorization80.product_request(o,w,e,a,op,'sync_endpoint','environment',e,false,false,false,true);
 IF p->>'credential_kind' IS DISTINCT FROM '2' OR p->'pat_ceiling' IS DISTINCT FROM '["sync_endpoint"]'::jsonb
 OR (op NOT IN('exchangeEndpointEnrollment','recordEndpointObservations') AND p#>>'{path_parameters,id}' IS DISTINCT FROM target_id)
 OR NOT COALESCE(public.zasp_valid_product_id(target_id) AND gen>0,false) THEN RAISE insufficient_privilege; END IF;
 k:=p->>'credential_id';
 SELECT * INTO d FROM public.zasp_endpoint_devices WHERE (organization_id,workspace_id,environment_id,id,credential_id,generation)=(o,w,e,target_id,k,gen) AND state<>'retired' FOR UPDATE;
 IF NOT FOUND OR (d.state='pending' AND op<>'exchangeEndpointEnrollment') THEN RETURN '"forbidden"'::jsonb; END IF;
 IF phase='key' THEN
  PERFORM zasp_authorization80.product_settled(p);RETURN jsonb_build_object('device_public_key',d.device_key);
 END IF;
 IF phase IS DISTINCT FROM 'apply' OR q->>'verified_key' IS DISTINCT FROM d.device_key OR NOT COALESCE(q->>'nonce'~'^[0-9a-f]{32}$' AND q->>'digest'~'^[0-9a-f]{64}$' AND (q->>'unix')::bigint BETWEEN current_time_unix-120 AND current_time_unix+30,false)
 OR octet_length(q::text)>65536 THEN RAISE insufficient_privilege; END IF;
 SELECT * INTO previous FROM public.zasp_endpoint_deliveries WHERE (organization_id,workspace_id,environment_id,device_id,generation,nonce)=(o,w,e,target_id,gen,q->>'nonce');
 IF FOUND THEN
  IF (previous.operation,previous.digest) IS DISTINCT FROM (op,q->>'digest') THEN RETURN '"conflict"'::jsonb; END IF;
  PERFORM zasp_authorization80.product_settled(p);RETURN previous.receipt;
 END IF;
 DELETE FROM public.zasp_endpoint_deliveries WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,target_id) AND recorded_at<clock_timestamp()-interval '3 minutes';
 IF (SELECT count(*)>=512 FROM public.zasp_endpoint_deliveries WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,target_id)) THEN RETURN '"capacity"'::jsonb; END IF;
 CASE op
 WHEN 'exchangeEndpointEnrollment' THEN
  IF v IS DISTINCT FROM '{}'::jsonb THEN RAISE invalid_parameter_value; END IF;
  UPDATE public.zasp_endpoint_devices SET state='active',enrolled_at=COALESCE(enrolled_at,clock_timestamp()),last_seen=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id);
  response_value:=jsonb_build_object('device_id',target_id,'credential_generation',gen,'state','active');
 WHEN 'fetchEndpointPolicy' THEN response_value:=jsonb_build_object('bundle',d.policy_bundle);
 WHEN 'recordEndpointHeartbeat' THEN
  IF NOT COALESCE(jsonb_typeof(v)='object' AND (v-ARRAY['policy_status','policy_revision','queued_receipts','dropped_receipts','adapter'])='{}'::jsonb
   AND (NOT v?'adapter' OR v->>'adapter' IN('macos_claude_ticket','linux_claude_ticket_test','windows_inventory'))
   AND (v->>'adapter' IS DISTINCT FROM 'windows_inventory' OR (v->>'policy_status'='policy_unavailable' AND v->>'policy_revision'='0' AND v->>'queued_receipts'='0' AND v->>'dropped_receipts'='0'))
   AND v->>'policy_status' IN('verified_cache','policy_expired','policy_unavailable','state_unavailable') AND (v->>'policy_revision')::bigint BETWEEN 0 AND 9007199254740992
   AND (v->>'queued_receipts')::integer BETWEEN 0 AND 256 AND (v->>'dropped_receipts')::bigint BETWEEN 0 AND 9007199254740992,false) THEN RAISE invalid_parameter_value; END IF;
  UPDATE public.zasp_endpoint_devices SET reported=v,reported_at=clock_timestamp(),last_seen=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,target_id);
 WHEN 'recordEndpointInventory' THEN
  IF NOT COALESCE(jsonb_typeof(v)='object' AND (v-ARRAY['partition_id','snapshot_generation','complete','installations'])='{}'::jsonb AND v->>'partition_id'~'^[0-9a-f]{64}$'
   AND jsonb_typeof(v->'complete')='boolean' AND (v->>'snapshot_generation')::bigint BETWEEN 1 AND 9007199254740992 AND jsonb_typeof(v->'installations')='array' AND jsonb_array_length(v->'installations')<=128
   AND NOT EXISTS(SELECT FROM jsonb_array_elements(v->'installations') x WHERE jsonb_typeof(x)<>'object' OR x-ARRAY['installation_id','manifest_digest']<>'{}'::jsonb OR NOT COALESCE(x->>'installation_id'~'^[0-9a-f]{64}$',false) OR (x?'manifest_digest' AND NOT COALESCE(x->>'manifest_digest'~'^sha256:[0-9a-f]{64}$',false))),false) THEN RAISE invalid_parameter_value; END IF;
  SELECT * INTO part FROM public.zasp_endpoint_partitions WHERE (organization_id,workspace_id,environment_id,device_id,partition_id)=(o,w,e,target_id,v->>'partition_id');
  IF FOUND AND (part.generation>(v->>'snapshot_generation')::bigint OR (part.generation=(v->>'snapshot_generation')::bigint AND part.observed<>v)) THEN RETURN '"conflict"'::jsonb; END IF;
  IF NOT FOUND AND (SELECT count(*)>=128 FROM public.zasp_endpoint_partitions WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,target_id)) THEN RETURN '"capacity"'::jsonb; END IF;
  INSERT INTO public.zasp_endpoint_partitions(organization_id,workspace_id,environment_id,device_id,partition_id,generation,observed,complete_snapshot,observed_at,complete_at) VALUES(o,w,e,target_id,v->>'partition_id',(v->>'snapshot_generation')::bigint,v,CASE WHEN (v->>'complete')::boolean THEN v END,clock_timestamp(),CASE WHEN (v->>'complete')::boolean THEN clock_timestamp() END)
   ON CONFLICT(organization_id,workspace_id,environment_id,device_id,partition_id) DO UPDATE SET generation=EXCLUDED.generation,observed=EXCLUDED.observed,
   complete_snapshot=COALESCE(EXCLUDED.complete_snapshot,zasp_endpoint_partitions.complete_snapshot),observed_at=EXCLUDED.observed_at,complete_at=COALESCE(EXCLUDED.complete_at,zasp_endpoint_partitions.complete_at)
   WHERE EXCLUDED.generation>zasp_endpoint_partitions.generation;
 WHEN 'recordEndpointObservations' THEN
  IF jsonb_typeof(v) IS DISTINCT FROM 'array' OR jsonb_array_length(v) NOT BETWEEN 1 AND 16 THEN RAISE invalid_parameter_value; END IF;
  -- Validate the whole batch before changing state so a conflicting later item
  -- cannot partially accept the batch.
  IF (SELECT count(DISTINCT j->>'action_id') FROM jsonb_array_elements(v) j)<>jsonb_array_length(v) THEN RETURN '"conflict"'::jsonb; END IF;
  FOR rec IN SELECT value FROM jsonb_array_elements(v) LOOP
   IF NOT COALESCE(jsonb_typeof(rec)='object' AND (rec-ARRAY['audience','binding','local_uid','action_id','session_ref','observed_at','policy_revision','mode','tool','target_class','verdict','would_block','reason','skill_usage','target_effect'])='{}'::jsonb
     AND rec->>'audience'='zasp.endpoint-observation.v1' AND rec->'binding'=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'device_id',target_id,'credential_generation',gen)
     AND rec->>'action_id'~'^[0-9a-f]{64}$' AND rec->>'session_ref'~'^[0-9a-f]{64}$' AND rec->>'tool'='mcp__pilot__update_ticket'
     AND rec->>'skill_usage'='unknown' AND rec->>'target_effect'='unknown' AND rec->>'verdict' IN('deny','continue','unavailable') AND rec->>'target_class' IN('allowed_destination','outside_allowed_destination','unknown')
     AND rec->>'mode' IN('','monitor','enforce') AND rec->>'reason' IN('policy_unavailable','policy_expired','state_unavailable','destination_not_approved','within_scope')
     AND jsonb_typeof(rec->'would_block')='boolean' AND (rec->>'local_uid')::bigint BETWEEN 0 AND 2147483647 AND (rec->>'policy_revision')::bigint>=0
     AND (rec->>'observed_at')::timestamptz<=clock_timestamp()+interval '30 seconds',false) THEN RAISE invalid_parameter_value; END IF;
   SELECT observation INTO seen FROM public.zasp_endpoint_observations WHERE (organization_id,workspace_id,environment_id,device_id,credential_generation,action_id)=(o,w,e,target_id,gen,rec->>'action_id');
   IF FOUND AND seen<>rec THEN RETURN '"conflict"'::jsonb; END IF;
  END LOOP;
  INSERT INTO public.zasp_endpoint_observations(organization_id,workspace_id,environment_id,device_id,credential_generation,action_id,observation)
   SELECT o,w,e,target_id,gen,x->>'action_id',x FROM jsonb_array_elements(v) x ON CONFLICT DO NOTHING;
 END CASE;
 INSERT INTO public.zasp_endpoint_deliveries(organization_id,workspace_id,environment_id,device_id,generation,nonce,operation,digest,receipt)
 VALUES(o,w,e,target_id,gen,q->>'nonce',op,q->>'digest',response_value);
 PERFORM zasp_authorization80.product_settled(p);RETURN response_value;
END $ep_machine$;
ALTER FUNCTION zasp_authorization80.endpoint_machine(text,text,text,text,text,text,bigint,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.endpoint_machine(text,text,text,text,text,text,bigint,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.endpoint_machine(text,text,text,text,text,text,bigint,text,jsonb) TO zasp_discovery_api;

-- Browser consent delegates only a short-lived private findings submission.
-- Public exchange has one input secret (PKCE). It cannot create a credential.
CREATE TABLE IF NOT EXISTS zasp_authorization80_identity.cli_authorizations (
 request_id text PRIMARY KEY CHECK(public.zasp_valid_product_id(request_id)),
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 principal_id text NOT NULL, credential_id text NOT NULL CHECK(public.zasp_valid_product_id(credential_id)),
 challenge text NOT NULL CHECK(challenge ~ '^[A-Za-z0-9_-]{43}$'),
 exchange_until timestamptz NOT NULL, token_until timestamptz NOT NULL, consumed_at timestamptz
);
ALTER TABLE zasp_authorization80_identity.cli_authorizations OWNER TO zasp_discovery_authority;
REVOKE ALL ON TABLE zasp_authorization80_identity.cli_authorizations FROM PUBLIC,zasp_discovery_api;
CREATE INDEX IF NOT EXISTS cli_authorizations_expiry ON zasp_authorization80_identity.cli_authorizations(exchange_until);

CREATE OR REPLACE FUNCTION zasp_authorization80.cli_approve(o text,w text,e text,actor text,req text,challenge_value text,token_hash text,exchange_epoch bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $cli_approve$
DECLARE proof jsonb; prior zasp_authorization80_identity.cli_authorizations%ROWTYPE;
 expiry timestamptz:=date_trunc('second',transaction_timestamp())+interval '15 minutes';
 until_value timestamptz; cred text:='pid_'||gen_random_uuid()::text; audit text:='pid_'||gen_random_uuid()::text;
 ceiling_value CONSTANT jsonb:='["submit_addon_scans"]'::jsonb; label_value CONSTANT text:='zaspctl findings submission';
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor,'approveCLILogin','manage_api_tokens','environment',e,false,true,true,true);
 IF NOT COALESCE(public.zasp_valid_product_id(req) AND challenge_value ~ '^[A-Za-z0-9_-]{43}$' AND token_hash ~ '^[a-f0-9]{64}$' AND
      exchange_epoch BETWEEN floor(extract(epoch FROM clock_timestamp())) AND floor(extract(epoch FROM clock_timestamp()))+301,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid CLI approval'; END IF;
 until_value:=to_timestamp(exchange_epoch);
 IF until_value<=clock_timestamp() THEN RETURN 'null'::jsonb; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp:cli-approve:'||req,0));
 SELECT * INTO prior FROM zasp_authorization80_identity.cli_authorizations WHERE request_id=req;
 IF FOUND THEN
  IF (prior.organization_id,prior.workspace_id,prior.environment_id,prior.principal_id,prior.challenge,prior.exchange_until) IS DISTINCT FROM (o,w,e,actor,challenge_value,until_value) THEN RETURN 'null'::jsonb; END IF;
  PERFORM zasp_authorization80.product_settled(proof); RETURN '{"approved":true}'::jsonb;
 END IF;
 -- Reuse the native PAT row guard with the exact data permitted to this
 -- manage_api_tokens principal. Its normal expiry, revocation, scope and
 -- OpenFGA rechecks continue to apply on every subsequent submission.
 PERFORM zasp_authorization80_identity.set_permit(jsonb_build_object('purpose','admin','operation','createAPIToken','organization_id',o,'workspace_id',w,'environment_id',e,'actor',actor,'audit_id',audit,
 'values',jsonb_build_object('token_digest',token_hash,'id',cred,'name',label_value,'permissions',ceiling_value,'expires_at',expiry)));
 INSERT INTO public.zasp_product_api_tokens(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at,id,name,audit_correlation_id)
 VALUES(decode(token_hash,'hex'),actor,o,w,e,ceiling_value,expiry,cred,label_value,audit);
 PERFORM zasp_authorization80_identity.clear_permit();
 INSERT INTO zasp_authorization80_identity.cli_authorizations(request_id,organization_id,workspace_id,environment_id,principal_id,credential_id,challenge,exchange_until,token_until)
 VALUES(req,o,w,e,actor,cred,challenge_value,until_value,expiry);
 INSERT INTO public.zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,principal_id,operation,resource_kind,resource_id,resource_version)
 VALUES(o,w,e,audit,req,actor,'approveCLILogin','api_token',cred,1);
 DELETE FROM zasp_authorization80_identity.cli_authorizations WHERE request_id IN (SELECT request_id FROM zasp_authorization80_identity.cli_authorizations WHERE exchange_until<clock_timestamp()-interval '1 day' ORDER BY exchange_until LIMIT 20);
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN '{"approved":true}'::jsonb;
END $cli_approve$;
ALTER FUNCTION zasp_authorization80.cli_approve(text,text,text,text,text,text,text,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.cli_approve(text,text,text,text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.cli_approve(text,text,text,text,text,text,text,bigint) TO zasp_discovery_api;

CREATE OR REPLACE FUNCTION zasp_authorization80_identity.cli_exchange(req text,e text,verifier text,expected_digest text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $cli_exchange$
DECLARE approved zasp_authorization80_identity.cli_authorizations%ROWTYPE;
BEGIN
 IF NOT zasp_authorization80_identity.api_ready() OR NOT COALESCE(public.zasp_valid_product_id(req) AND public.zasp_valid_product_id(e) AND verifier ~ '^[A-Za-z0-9_-]{43}$' AND expected_digest ~ '^[a-f0-9]{64}$',false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='CLI exchange unavailable'; END IF;
 UPDATE zasp_authorization80_identity.cli_authorizations g SET consumed_at=clock_timestamp()
 WHERE request_id=req AND environment_id=e AND consumed_at IS NULL AND exchange_until>clock_timestamp()
 AND challenge=translate(rtrim(encode(public.digest(verifier,'sha256'),'base64'),'='),'+/','-_')
 AND EXISTS(SELECT 1 FROM public.zasp_product_api_tokens t WHERE t.id=g.credential_id AND t.organization_id=g.organization_id AND t.workspace_id=g.workspace_id
 AND t.environment_id=e AND t.token_digest=decode(expected_digest,'hex') AND t.principal_id=g.principal_id AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND t.permissions='["submit_addon_scans"]'::jsonb)
 RETURNING g.* INTO approved;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 RETURN jsonb_build_object('expires_at',approved.token_until);
END $cli_exchange$;
ALTER FUNCTION zasp_authorization80_identity.cli_exchange(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80_identity.cli_exchange(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80_identity.cli_exchange(text,text,text,text) TO zasp_discovery_api;

-- Purpose changes are explicit, append-only reviewer declarations. They do not
-- change effective policy. Tool identifiers are selectors within this scope;
-- reading a declaration confers no access to the referenced tool objects.
CREATE TABLE IF NOT EXISTS public.zasp_agent_purpose_versions (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 agent_id text NOT NULL, revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
 actor text NOT NULL, request_key text NOT NULL, allowed_tool_ids jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (organization_id,workspace_id,environment_id,agent_id,revision),
 UNIQUE (organization_id,workspace_id,environment_id,agent_id,actor,request_key)
);
ALTER TABLE public.zasp_agent_purpose_versions OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_agent_purpose_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_agent_purpose_versions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_agent_purpose_versions FROM PUBLIC;
DO $purpose_rls$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_agent_purpose_versions' AND policyname='purpose_scope_authority') THEN
  CREATE POLICY purpose_scope_authority ON public.zasp_agent_purpose_versions TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $purpose_rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.agent_purpose_value(o text,w text,e text,i text,n bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $purpose_value$
 SELECT jsonb_build_object('agent_id',i,'revision',revision,'allowed_tool_ids',allowed_tool_ids,'updated_at',to_char(updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id,revision)=(o,w,e,i,n)
$purpose_value$;
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_purpose_get(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $purpose_get$
DECLARE n bigint;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getAgentPurpose','view','agent',i,true,true,false,false);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent')) THEN RETURN 'null'::jsonb; END IF;
 SELECT max(revision) INTO n FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i);
 RETURN coalesce(zasp_authorization80.agent_purpose_value(o,w,e,i,n),jsonb_build_object('agent_id',i,'revision',0,'allowed_tool_ids','[]'::jsonb,'updated_at',NULL));
END $purpose_get$;
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_purpose_put(o text,w text,e text,a text,i text,k text,n bigint,tools jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $purpose_put$
DECLARE latest bigint; prior public.zasp_agent_purpose_versions%ROWTYPE;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,a,'putAgentPurpose','manage_workflows','agent',i,true,true,false,true);
 IF k IS NULL OR k !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' OR n IS NULL OR n NOT BETWEEN 0 AND 999999 OR jsonb_typeof(tools) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid purpose'; END IF;
 IF jsonb_array_length(tools)>64 OR EXISTS(SELECT 1 FROM jsonb_array_elements(tools) t(value) WHERE jsonb_typeof(value) <> 'string' OR NOT public.zasp_valid_product_id(value #>> '{}')) OR jsonb_array_length(tools)<>(SELECT count(DISTINCT v) FROM jsonb_array_elements_text(tools) t(v)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid purpose tools'; END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v),'[]'::jsonb) INTO tools FROM jsonb_array_elements_text(tools) t(v);
 PERFORM id FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT * INTO prior FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id,actor,request_key)=(o,w,e,i,a,k);
 IF FOUND THEN IF prior.revision=n+1 AND prior.allowed_tool_ids=tools THEN RETURN zasp_authorization80.agent_purpose_value(o,w,e,i,prior.revision); END IF; RETURN '"conflict"'::jsonb; END IF;
 SELECT coalesce(max(revision),0) INTO latest FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i);
 IF latest<>n THEN RETURN '"conflict"'::jsonb; END IF;
 INSERT INTO public.zasp_agent_purpose_versions(organization_id,workspace_id,environment_id,agent_id,revision,actor,request_key,allowed_tool_ids) VALUES(o,w,e,i,n+1,a,k,tools);
 RETURN zasp_authorization80.agent_purpose_value(o,w,e,i,n+1);
END $purpose_put$;
DO $purpose_grants$ DECLARE f text; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.agent_purpose_value(text,text,text,text,bigint)','zasp_authorization80.agent_purpose_get(text,text,text,text)','zasp_authorization80.agent_purpose_put(text,text,text,text,text,text,bigint,jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f::regprocedure);
  IF f NOT LIKE '%agent_purpose_value%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f::regprocedure); END IF;
 END LOOP;
END $purpose_grants$;

-- A repository signer attests the manifest independently of the upload token.
-- Only public keys enter this database. A trusted signature is checked by the
-- API on admission and again when a human reads the evidence. No SQL label
-- or report field by itself confers trusted provenance or execution rights.
CREATE TABLE IF NOT EXISTS public.zasp_addon_ci_keys (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 credential_id text NOT NULL, key_id text NOT NULL CHECK(key_id ~ '^[0-9a-f]{64}$'), repository text NOT NULL,
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32), revoked_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id,key_id)
);
CREATE TABLE IF NOT EXISTS public.zasp_addon_ci_origins (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, scan_id text NOT NULL,
 credential_id text NOT NULL, key_id text NOT NULL, commit_sha text NOT NULL CHECK(commit_sha ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'),
 signature bytea NOT NULL CHECK(octet_length(signature)=64), manifest_digest text NOT NULL, admitted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,scan_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,scan_id) REFERENCES public.zasp_addon_scan_receipts(organization_id,workspace_id,environment_id,scan_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,credential_id,key_id) REFERENCES public.zasp_addon_ci_keys(organization_id,workspace_id,environment_id,credential_id,key_id)
);
CREATE INDEX IF NOT EXISTS zasp_addon_ci_manifest_idx ON public.zasp_addon_ci_origins(organization_id,workspace_id,environment_id,manifest_digest,admitted_at DESC,scan_id);
DO $ci_tables$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['zasp_addon_ci_keys','zasp_addon_ci_origins'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',name);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',name);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=name AND policyname=name||'_authority') THEN EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL TO zasp_discovery_authority USING(true) WITH CHECK(true)',name||'_authority',name); END IF;
 END LOOP;
END $ci_tables$;

CREATE OR REPLACE FUNCTION zasp_authorization80.register_addon_ci_key(o text,w text,e text,c text,repo text,raw_key bytea,retire boolean) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ci_register$
DECLARE kid text;
BEGIN
 IF session_user<>'zasp_operator' OR NOT COALESCE(octet_length(raw_key)=32 AND repo ~ '^[a-z0-9][a-z0-9.-]{0,38}/[a-z0-9][a-z0-9._-]{0,99}$' AND retire IS NOT NULL,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='CI key registration denied'; END IF;
 kid:=encode(public.digest(raw_key,'sha256'),'hex');
 IF retire THEN
  UPDATE public.zasp_addon_ci_keys SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE (organization_id,workspace_id,environment_id,credential_id,key_id,repository)=(o,w,e,c,kid,repo);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='CI signer unavailable'; END IF;
 ELSE
  IF NOT EXISTS(SELECT FROM public.zasp_product_api_tokens t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.id)=(o,w,e,c) AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND t.permissions='["submit_addon_scans"]'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='CI token is unavailable'; END IF;
  INSERT INTO public.zasp_addon_ci_keys(organization_id,workspace_id,environment_id,credential_id,key_id,repository,public_key) VALUES(o,w,e,c,kid,repo,raw_key) ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT FROM public.zasp_addon_ci_keys WHERE (organization_id,workspace_id,environment_id,credential_id,key_id,repository,public_key)=(o,w,e,c,kid,repo,raw_key) AND revoked_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='CI signer binding differs or is revoked'; END IF;
 END IF;
 RETURN kid;
END $ci_register$;

CREATE OR REPLACE FUNCTION zasp_authorization80.addon_ci_binding(o text,w text,e text,actor_value text,i text,kid text,repo text,write_value boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ci_binding$
DECLARE p jsonb; v jsonb;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,actor_value,'attestAddonScan','submit_addon_scans','environment',e,false,false,false,write_value);
 IF p->>'credential_kind' IS DISTINCT FROM '2' OR p->'pat_ceiling' IS DISTINCT FROM '["submit_addon_scans"]'::jsonb OR p#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='restricted CI credential required'; END IF;
 SELECT jsonb_build_object('environment_id',e,'credential_id',s.credential_id,'scan_id',s.scan_id,'manifest_digest',s.report->>'manifest_digest','ruleset',s.report->>'ruleset','findings',s.report->'findings','key_id',k.key_id,'repository',k.repository,'public_key',encode(k.public_key,'hex')) INTO v FROM public.zasp_addon_scan_receipts s JOIN public.zasp_addon_ci_keys k USING(organization_id,workspace_id,environment_id,credential_id) WHERE (s.organization_id,s.workspace_id,s.environment_id,s.credential_id,s.scan_id,k.key_id,k.repository)=(o,w,e,p->>'credential_id',i,kid,repo) AND s.report->>'origin'='ci' AND s.report->>'completeness'='complete' AND k.revoked_at IS NULL FOR SHARE OF k;
 RETURN COALESCE(v,'null'::jsonb);
END $ci_binding$;
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_ci_record(o text,w text,e text,actor_value text,i text,kid text,repo text,csha text,sig bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ci_record$
DECLARE v jsonb; prior public.zasp_addon_ci_origins%ROWTYPE;
BEGIN
 v:=zasp_authorization80.addon_ci_binding(o,w,e,actor_value,i,kid,repo,true);IF v='null'::jsonb THEN RETURN v;END IF;
 INSERT INTO public.zasp_addon_ci_origins(organization_id,workspace_id,environment_id,credential_id,key_id,scan_id,manifest_digest,commit_sha,signature) VALUES(o,w,e,v->>'credential_id',kid,i,v->>'manifest_digest',csha,sig) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT prior FROM public.zasp_addon_ci_origins WHERE (organization_id,workspace_id,environment_id,scan_id)=(o,w,e,i);
 IF (prior.key_id,prior.commit_sha,prior.signature) IS DISTINCT FROM (kid,csha,sig) THEN RETURN '"conflict"'::jsonb; END IF;
 RETURN jsonb_build_object('scan_id',i,'repository',repo,'commit',csha);
END $ci_record$;
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_ci_origin(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ci_origin$
DECLARE p jsonb; digest_value text; result jsonb;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,NULL,'getAddonCIOrigin','view','environment',e,false,true,false,false);
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong add-on scope'; END IF;
 SELECT manifest_digest INTO digest_value FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i); IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT COALESCE(jsonb_agg(row_info),'[]'::jsonb) INTO result FROM (
  SELECT jsonb_build_object('environment_id',e,'credential_id',s.credential_id,'scan_id',s.scan_id,'manifest_digest',s.report->>'manifest_digest','ruleset',s.report->>'ruleset','findings',s.report->'findings','key_id',k.key_id,'repository',k.repository,'public_key',encode(k.public_key,'hex'),'commit',a.commit_sha,'signature',encode(a.signature,'hex'),'direct',s.receipt->>'version_id'=i) row_info
  FROM public.zasp_addon_ci_origins a JOIN public.zasp_addon_scan_receipts s USING(organization_id,workspace_id,environment_id,scan_id,credential_id) JOIN public.zasp_addon_ci_keys k USING(organization_id,workspace_id,environment_id,credential_id,key_id)
  WHERE (a.organization_id,a.workspace_id,a.environment_id,a.manifest_digest)=(o,w,e,digest_value) AND k.revoked_at IS NULL AND s.report->>'manifest_digest'=digest_value
  ORDER BY (s.receipt->>'version_id'=i) DESC,a.admitted_at DESC,a.scan_id LIMIT 16
 ) candidates; RETURN result;
END $ci_origin$;
DO $ci_grants$
DECLARE f record;
BEGIN
 FOR f IN SELECT * FROM (VALUES
  ('zasp_authorization80.register_addon_ci_key(text,text,text,text,text,bytea,boolean)',NULL),
  ('zasp_authorization80.addon_ci_binding(text,text,text,text,text,text,text,boolean)','zasp_discovery_api'),
  ('zasp_authorization80.addon_ci_record(text,text,text,text,text,text,text,text,bytea)','zasp_discovery_api'),
  ('zasp_authorization80.addon_ci_origin(text,text,text,text)','zasp_discovery_api')) v(signature,grantee) LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f.signature::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature::regprocedure);
  IF f.grantee IS NULL THEN
   -- The operator inherits the owner role for registration, as it does for register_verifier.
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM zasp_operator',f.signature::regprocedure);
  ELSE EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',f.signature::regprocedure,f.grantee); END IF;
 END LOOP;
END $ci_grants$;

-- A dedicated agent/session PAT is an explicit administrator assignment.
-- Claiming an agent or session in a request body or header cannot create it.
CREATE TABLE IF NOT EXISTS public.zasp_workload_bindings (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 credential_id text NOT NULL, agent_id text NOT NULL, session_id text NOT NULL,
 created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id),
 UNIQUE(organization_id,workspace_id,environment_id,session_id)
);
ALTER TABLE public.zasp_workload_bindings OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_workload_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_workload_bindings FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_workload_bindings FROM PUBLIC;
DO $binding_rls$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_workload_bindings' AND policyname='workload_binding_authority') THEN
  CREATE POLICY workload_binding_authority ON public.zasp_workload_bindings TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $binding_rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_binding(o text,w text,e text,actor text,token_value text,agent_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $binding$
DECLARE p jsonb; b public.zasp_workload_bindings%ROWTYPE; op text;
BEGIN
 op:=CASE WHEN agent_value IS NULL THEN 'getWorkloadCredentialBinding' ELSE 'bindWorkloadCredential' END;
 p:=zasp_authorization80.product_request(o,w,e,actor,op,'manage_api_tokens','environment',e,false,true,agent_value IS NOT NULL,agent_value IS NOT NULL);
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM token_value OR NOT public.zasp_valid_product_id(token_value) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload credential path required'; END IF;
 IF agent_value IS NOT NULL THEN
  -- Mixing a human read or management token with a permanent workload identity
  -- would let unrelated requests be attributed to that workload.
  PERFORM 1 FROM public.zasp_product_api_tokens t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.id)=(o,w,e,token_value)
   AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND jsonb_array_length(t.permissions)>0
   AND t.permissions <@ '["use_gateway","decide_actions"]'::jsonb FOR SHARE;
  IF NOT FOUND THEN RETURN '{"error":"ineligible_binding"}'::jsonb; END IF;
  PERFORM 1 FROM public.zasp_inventory_entities i WHERE (i.organization_id,i.workspace_id,i.environment_id,i.id,i.product_kind,i.state)=(o,w,e,agent_value,'agent','active') FOR SHARE;
  IF NOT FOUND THEN RETURN '{"error":"ineligible_binding"}'::jsonb; END IF;
  INSERT INTO public.zasp_workload_bindings(organization_id,workspace_id,environment_id,credential_id,agent_id,session_id,created_by)
   VALUES(o,w,e,token_value,agent_value,public.zasp_discovery_canonical_id(o,w,e,'bound_workload_session',token_value),actor)
   ON CONFLICT(organization_id,workspace_id,environment_id,credential_id) DO NOTHING;
 END IF;
 SELECT * INTO b FROM public.zasp_workload_bindings WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,token_value);
 IF NOT FOUND THEN RETURN '{"error":"unknown_binding"}'::jsonb; END IF;
 IF agent_value IS NOT NULL AND b.agent_id<>agent_value THEN RETURN '{"error":"binding_conflict"}'::jsonb; END IF;
 IF agent_value IS NOT NULL THEN PERFORM zasp_authorization80.product_settled(p); END IF;
 RETURN jsonb_build_object('credential_id',b.credential_id,'agent_id',b.agent_id,'session_id',b.session_id,'source','administrator_bound_credential','created_by',b.created_by,'created_at',b.created_at);
END $binding$;
ALTER FUNCTION zasp_authorization80.workload_binding(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_binding(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_binding(text,text,text,text,text,text) TO zasp_discovery_api;

-- Bind at ingestion, so a later registration cannot rewrite historical facts.
ALTER TABLE public.zasp_gateway_decisions ADD COLUMN IF NOT EXISTS bound_session_id text;
CREATE OR REPLACE FUNCTION zasp_authorization80.gateway_record_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $attach$
DECLARE p jsonb:=zasp_authorization80.context(); b public.zasp_workload_bindings%ROWTYPE;
BEGIN
 IF p->>'credential_kind'='2' AND p->'pat_ceiling'?'use_gateway'
  AND p->>'operation_id' IN ('callMCPGateway','closeMCPGatewaySession','createGatewayChatCompletion','createGatewayResponse','createGatewayMessage')
  AND (p->>'organization_id',p->>'workspace_id',p->>'environment_id',p->>'principal_id')=
    (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.principal_id) THEN
  SELECT * INTO b FROM public.zasp_workload_bindings WHERE (organization_id,workspace_id,environment_id,credential_id)=
    (NEW.organization_id,NEW.workspace_id,NEW.environment_id,p->>'credential_id');
  IF FOUND THEN NEW.agent_id:=b.agent_id; NEW.bound_session_id:=b.session_id; NEW.session_pending:=true; END IF;
 END IF;
 RETURN NEW;
END $attach$;
ALTER FUNCTION zasp_authorization80.gateway_record_binding() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.gateway_record_binding() FROM PUBLIC;
CREATE OR REPLACE TRIGGER zasp_capture_gateway_binding BEFORE INSERT ON public.zasp_gateway_decisions FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.gateway_record_binding();

-- Preserve the historical, caller-claimed daily rollup for unbound tokens.
DO $bound_projection$
DECLARE fn regprocedure:='public.zasp_gateway_maintain(integer,integer)'::regprocedure;
 original text:=pg_get_functiondef(fn);
 old_value CONSTANT text:=$v$public.zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'gateway_session',d.agent_id||'/'||to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD')),
    d.agent_id,'strong','gateway'$v$;
 new_value CONSTANT text:=$v$COALESCE(d.bound_session_id,public.zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'gateway_session',d.agent_id||'/'||to_char(d.created_at AT TIME ZONE 'UTC','YYYY-MM-DD'))),
    d.agent_id,CASE WHEN d.bound_session_id IS NOT NULL THEN 'exact' ELSE 'strong' END,'gateway'$v$;
BEGIN
 IF position(new_value IN original)=0 THEN
  IF position(old_value IN original)=0 THEN RAISE EXCEPTION 'unrecognized hosted session projection'; END IF;
  EXECUTE replace(original,old_value,new_value);
 END IF;
END $bound_projection$;

-- Explicit extension of one already-approved runtime gateway session isolation
-- onto one administered workload credential governing that same session.
CREATE TABLE IF NOT EXISTS public.zasp_workload_containments(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,credential_id text NOT NULL,run_id text NOT NULL,
 step_id text NOT NULL,approval_id text NOT NULL,source_device_id text NOT NULL,session_id text NOT NULL,authorized_by text NOT NULL,
 authorized_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,released_at timestamptz,released_by text,
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,credential_id) REFERENCES public.zasp_workload_bindings(organization_id,workspace_id,environment_id,credential_id),
 CHECK((released_at IS NULL)=(released_by IS NULL)), CHECK(expires_at>authorized_at)
);
ALTER TABLE public.zasp_workload_containments OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_workload_containments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_workload_containments FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_workload_containments FROM PUBLIC;
DO $controls_rls$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_workload_containments' AND policyname='workload_control_authority') THEN
  CREATE POLICY workload_control_authority ON public.zasp_workload_containments TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $controls_rls$;
ALTER TABLE public.zasp_workload_actions ADD COLUMN IF NOT EXISTS containment_runs text[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS zasp_workload_actions_binding_time ON public.zasp_workload_actions(organization_id,workspace_id,environment_id,credential_id,created_at DESC);

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_control_end(c public.zasp_workload_containments) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $control_end$
 SELECT least(c.expires_at,c.released_at,(SELECT min(t.verified_at) FROM public.zasp_security_agent_temporary_policy_targets t
  WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.device_id,t.action_key,t.phase,t.state)=
   (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.step_id,c.source_device_id,'isolate_session','cleanup','verified')))
$control_end$;
ALTER FUNCTION zasp_authorization80.workload_control_end(public.zasp_workload_containments) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_control_end(public.zasp_workload_containments) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_containment(o text,w text,e text,actor text,token_value text,run_value text,step_value text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $contain$
DECLARE p jsonb; op text; b public.zasp_workload_bindings%ROWTYPE; c public.zasp_workload_containments%ROWTYPE; source record;
 end_time timestamptz; applied text; resumed text; state_value text;
BEGIN
 op:=zasp_authorization80.context()->>'operation_id';
 IF op IS NULL OR op NOT IN ('authorizeWorkloadContainment','releaseWorkloadContainment','getWorkloadContainment') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload containment operation required'; END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,op,'revoke_sessions','environment',e,false,true,op<>'getWorkloadContainment',op<>'getWorkloadContainment');
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM token_value OR p#>>'{path_parameters,runId}' IS DISTINCT FROM run_value THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workload containment path required'; END IF;
 SELECT * INTO b FROM public.zasp_workload_bindings WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,token_value);
 IF NOT FOUND THEN RETURN '{"error":"unknown_binding"}'::jsonb; END IF;
 -- Serialize approval, release and admission for this binding. This also
 -- prevents a release or policy expiry race from reusing an earlier grant.
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),'workload-controls',o,w,e,token_value),0));
 SELECT * INTO c FROM public.zasp_workload_containments WHERE (organization_id,workspace_id,environment_id,credential_id,run_id)=(o,w,e,token_value,run_value);
 IF op='authorizeWorkloadContainment' THEN
  IF NOT public.zasp_valid_product_id(step_value) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid step'; END IF;
  IF c.run_id IS NOT NULL AND c.step_id<>step_value THEN RETURN '{"error":"containment_conflict"}'::jsonb; END IF;
  IF c.run_id IS NULL THEN
   SELECT t.device_id,t.expires_at,a.approval_id INTO source FROM public.zasp_security_agent_temporary_policy_targets t
   JOIN public.zasp_security_agent_plans plan ON (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(o,w,e,t.run_id)
   JOIN public.zasp_security_agent_approvals a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.plan_hash,a.state)=(o,w,e,t.run_id,t.step_id,plan.plan_hash,'approved')
   WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.action_key,t.phase,t.state)=(o,w,e,run_value,step_value,'isolate_session','apply','verified')
    AND t.verified_at IS NOT NULL AND t.expires_at>clock_timestamp()
    AND plan.plan->'steps' @> jsonb_build_array(jsonb_build_object('action','isolate_session','device_id',t.device_id,'session_id',b.session_id,'step_id',step_value,'scope',e))
    AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets cleanup WHERE
     (cleanup.organization_id,cleanup.workspace_id,cleanup.environment_id,cleanup.run_id,cleanup.step_id,cleanup.device_id,cleanup.phase,cleanup.state)=(o,w,e,run_value,step_value,t.device_id,'cleanup','verified'));
   IF NOT FOUND THEN RETURN '{"error":"unverified_source"}'::jsonb; END IF;
   INSERT INTO public.zasp_workload_containments(organization_id,workspace_id,environment_id,credential_id,run_id,step_id,approval_id,source_device_id,session_id,authorized_by,expires_at)
   VALUES(o,w,e,token_value,run_value,step_value,source.approval_id,source.device_id,b.session_id,actor,source.expires_at) RETURNING * INTO c;
  END IF;
 ELSIF c.run_id IS NULL THEN RETURN '{"error":"unknown_control"}'::jsonb;
 ELSIF op='releaseWorkloadContainment' AND c.released_at IS NULL THEN
  UPDATE public.zasp_workload_containments SET released_at=clock_timestamp(),released_by=actor
   WHERE (organization_id,workspace_id,environment_id,credential_id,run_id)=(o,w,e,token_value,run_value) RETURNING * INTO c;
 END IF;
 end_time:=zasp_authorization80.workload_control_end(c);
 SELECT x.receipt->>'decision_id' INTO applied FROM public.zasp_workload_actions x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.credential_id)=(o,w,e,token_value)
  AND run_value=ANY(x.containment_runs) AND x.outcome->>'status'='not_dispatched' ORDER BY x.created_at DESC LIMIT 1;
 IF end_time<=clock_timestamp() THEN
  state_value:=CASE WHEN c.released_at IS NOT NULL OR end_time<c.expires_at THEN 'released' ELSE 'expired' END;
  SELECT x.receipt->>'decision_id' INTO resumed FROM public.zasp_workload_actions x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.credential_id)=(o,w,e,token_value)
   AND x.created_at>=end_time AND x.outcome IS NOT NULL AND NOT(run_value=ANY(x.containment_runs)) ORDER BY x.created_at DESC LIMIT 1;
 ELSE state_value:=CASE WHEN applied IS NULL THEN 'pending_readback' ELSE 'adapter_confirmed' END; END IF;
 IF op<>'getWorkloadContainment' THEN PERFORM zasp_authorization80.product_settled(p); END IF;
 RETURN jsonb_build_object('credential_id',token_value,'run_id',run_value,'step_id',c.step_id,'session_id',c.session_id,'approval_id',c.approval_id,
  'authorized_by',c.authorized_by,'authorized_at',c.authorized_at,'expires_at',c.expires_at,'state',state_value,'block_receipt_id',applied,'release_receipt_id',resumed);
END $contain$;
ALTER FUNCTION zasp_authorization80.workload_containment(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.workload_containment(text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workload_containment(text,text,text,text,text,text,text) TO zasp_discovery_api;

-- An authorized investigator imports metadata from an independent recorder
-- alongside adapter evidence. This supplement does not set the run verdict.
CREATE TABLE IF NOT EXISTS public.zasp_ticket_verification_imports (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, definition_version bigint NOT NULL, submitted_by text NOT NULL,
 submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), bundle jsonb NOT NULL,
 PRIMARY KEY (organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY (organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id) ON DELETE CASCADE
);
ALTER TABLE public.zasp_ticket_verification_imports OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_ticket_verification_imports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_ticket_verification_imports FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_ticket_verification_imports FROM PUBLIC;
DO $ticket_rls$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_ticket_verification_imports' AND policyname='ticket_proof_authority') THEN
  CREATE POLICY ticket_proof_authority ON public.zasp_ticket_verification_imports TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $ticket_rls$;
CREATE OR REPLACE FUNCTION zasp_authorization80.ticket_proof_read(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $ticket_value$
 SELECT jsonb_build_object('submitted_by',submitted_by,'submitted_at',submitted_at,'definition_version',definition_version,'bundle',bundle,'digest',encode(sha256(convert_to(bundle::text,'UTF8')),'hex')) FROM public.zasp_ticket_verification_imports WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)
$ticket_value$;
CREATE OR REPLACE FUNCTION zasp_authorization80.ticket_proof_get(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $ticket_get$
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getTicketVerification','view','test_run',r,true,true,false,false);
 RETURN coalesce(zasp_authorization80.ticket_proof_read(o,w,e,r),'null'::jsonb);
END $ticket_get$;
CREATE OR REPLACE FUNCTION zasp_authorization80.ticket_proof_put(o text,w text,e text,a text,r text,b jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $ticket_put$
DECLARE current_run public.zasp_red_team_runs%ROWTYPE; definition public.zasp_red_team_definitions%ROWTYPE; previous jsonb; scenario jsonb:=b->'scenario';
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,a,'putTicketVerification','run_tests','test_run',r,true,true,false,true);
 IF b IS NULL OR octet_length(b::text)>65536 OR jsonb_typeof(b) IS DISTINCT FROM 'object' OR b - ARRAY['scenario','adapter','recorder'] <> '{}'::jsonb OR NOT(b ?& ARRAY['scenario','adapter','recorder']) OR scenario->>'schema_version' IS DISTINCT FROM 'zasp-ticket-proof-v1' OR scenario->>'operation' IS DISTINCT FROM 'synthetic_ticket_update' OR scenario->>'run_id' IS DISTINCT FROM r OR scenario->'scope' IS DISTINCT FROM jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e) OR scenario->>'credential_class' IS DISTINCT FROM 'test_write' OR NOT COALESCE(scenario->>'environment' IN('staging','test','development'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid ticket experiment'; END IF;
 SELECT * INTO current_run FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT bundle INTO previous FROM public.zasp_ticket_verification_imports WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN IF previous<>b THEN RETURN '"conflict"'::jsonb; END IF; RETURN zasp_authorization80.ticket_proof_read(o,w,e,r); END IF;
 SELECT * INTO definition FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,current_run.definition_id,current_run.definition_version) FOR SHARE;
 IF NOT FOUND OR definition.target_id IS DISTINCT FROM scenario->>'target_id' OR definition.safety->>'environment' IS DISTINCT FROM scenario->>'environment' OR definition.safety->>'credential_class' IS DISTINCT FROM 'test_write' OR NOT coalesce((definition.safety->'expected_side_effects') ? 'synthetic_ticket_update',false) OR NOT EXISTS (SELECT 1 FROM public.zasp_environments env WHERE (env.organization_id,env.workspace_id,env.id,env.environment_class)=(o,w,e,scenario->>'environment')) OR (scenario->>'window_start')::timestamptz < current_run.queued_at OR (scenario->>'window_end')::timestamptz > clock_timestamp() THEN RETURN '"ineligible"'::jsonb; END IF;
 INSERT INTO public.zasp_ticket_verification_imports(organization_id,workspace_id,environment_id,run_id,definition_version,submitted_by,bundle) VALUES(o,w,e,r,current_run.definition_version,a,b);
 RETURN zasp_authorization80.ticket_proof_read(o,w,e,r);
END $ticket_put$;
DO $ticket_grants$ DECLARE f text; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.ticket_proof_read(text,text,text,text)','zasp_authorization80.ticket_proof_get(text,text,text,text)','zasp_authorization80.ticket_proof_put(text,text,text,text,text,jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f::regprocedure);
  IF f NOT LIKE '%ticket_proof_read%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f::regprocedure); END IF;
 END LOOP;
END $ticket_grants$;

-- Retained pilot exports reuse the job, worker lease, fresh browser grant and
-- download authorities. New selectors never mix with framework or agent exports.
CREATE OR REPLACE FUNCTION zasp_authorization80.pilot_export_visible(o text,w text,e text,q jsonb) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog AS $pilot_select$
 SELECT CASE WHEN q ? 'pilot_cohort' THEN
   q - 'pilot_cohort'='{}'::jsonb AND jsonb_typeof(q->'pilot_cohort')='string' AND (q->>'pilot_cohort')~'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
   AND EXISTS(SELECT FROM public.zasp_endpoint_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.cohort)=(o,w,e,q->>'pilot_cohort'))
 ELSE q ? 'device_id' AND q - ARRAY['device_id','endpoint_session_ref']='{}'::jsonb AND jsonb_typeof(q->'device_id')='string' AND public.zasp_valid_product_id(q->>'device_id')
   AND EXISTS(SELECT FROM public.zasp_endpoint_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.id)=(o,w,e,q->>'device_id'))
   AND (NOT q?'endpoint_session_ref' OR (jsonb_typeof(q->'endpoint_session_ref')='string' AND (q->>'endpoint_session_ref')~'^[0-9a-f]{64}$'
     AND EXISTS(SELECT FROM public.zasp_endpoint_observations b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.device_id)=(o,w,e,q->>'device_id') AND b.observation->>'session_ref'=q->>'endpoint_session_ref'))) END
$pilot_select$;
ALTER FUNCTION zasp_authorization80.pilot_export_visible(text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.pilot_export_visible(text,text,text,jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION zasp_authorization80.pilot_export_pack(o text,w text,e text,q jsonb,stamp timestamptz) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog AS $pilot_pack$
 WITH devices AS MATERIALIZED (
   SELECT d.id,d.state,d.cohort,d.last_seen,zasp_authorization80.endpoint_view(d) AS status
   FROM public.zasp_endpoint_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id)=(o,w,e)
   AND ((q?'pilot_cohort' AND d.cohort=q->>'pilot_cohort') OR (q?'device_id' AND d.id=q->>'device_id')) ORDER BY d.id COLLATE "C" LIMIT 101),
 shown AS MATERIALIZED (SELECT * FROM devices ORDER BY id COLLATE "C" LIMIT 100),
 actions AS MATERIALIZED (
   SELECT b.device_id,b.credential_generation,b.action_id,b.received_at,b.observation FROM public.zasp_endpoint_observations b
   JOIN shown d ON d.id=b.device_id WHERE (b.organization_id,b.workspace_id,b.environment_id)=(o,w,e)
   AND (NOT q?'endpoint_session_ref' OR b.observation->>'session_ref'=q->>'endpoint_session_ref')
   ORDER BY b.received_at DESC,b.device_id,b.credential_generation,b.action_id LIMIT 101),
 installs AS MATERIALIZED (
   SELECT p.device_id,p.partition_id,p.generation,item FROM public.zasp_endpoint_partitions p JOIN shown d ON p.device_id=d.id
   CROSS JOIN LATERAL jsonb_array_elements(p.observed->'installations') item WHERE (p.organization_id,p.workspace_id,p.environment_id)=(o,w,e)
   ORDER BY p.device_id,p.partition_id,item->>'installation_id' LIMIT 101)
 SELECT jsonb_build_object('schema_version','managed-pilot-evidence.v1','organization_id',o,'workspace_id',w,'environment_id',e,'captured_at',stamp,'selection',q,
  'assigned_fleet','unknown','external_verification','unknown','target_effect','unknown','skill_usage','unknown',
  'devices_truncated',(SELECT count(*)>100 FROM devices),
  'actions_truncated',(SELECT count(*)>100 FROM actions) OR (SELECT count(*)>100 FROM devices),
  'installations_truncated',(SELECT count(*)>100 FROM installs) OR (SELECT count(*)>100 FROM devices),
  'devices',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',id,'cohort',cohort,'state',state,'last_seen',last_seen,
   'connection',status->>'connection','issued_revision',status->'policy_revision','reported_revision',status->'reported_policy_revision','acknowledged',status->'acknowledged') ORDER BY id) FROM shown),'[]'::jsonb),
  'observations',COALESCE((SELECT jsonb_agg(jsonb_build_object('device_id',device_id,'generation',credential_generation,'action_ref',action_id,'session_ref',observation->>'session_ref',
   'received_at',received_at,'policy_revision',observation->'policy_revision','mode',observation->>'mode','verdict',observation->>'verdict','would_block',observation->'would_block') ORDER BY received_at DESC,device_id,credential_generation,action_id)
    FROM (SELECT * FROM actions ORDER BY received_at DESC,device_id,credential_generation,action_id LIMIT 100) a),'[]'::jsonb),
  'installations',COALESCE((SELECT jsonb_agg(jsonb_build_object('device_id',device_id,'installation_ref',item->>'installation_id','generation',generation,'manifest_digest',item->'manifest_digest') ORDER BY device_id,partition_id,item->>'installation_id')
    FROM (SELECT * FROM installs ORDER BY device_id,partition_id,item->>'installation_id' LIMIT 100) i),'[]'::jsonb))
$pilot_pack$;
ALTER FUNCTION zasp_authorization80.pilot_export_pack(text,text,text,jsonb,timestamptz) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.pilot_export_pack(text,text,text,jsonb,timestamptz) FROM PUBLIC;

DO $pilot_exports$
DECLARE target record; d text; step record;
BEGIN
 FOR target IN SELECT * FROM (VALUES ('public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)','create'),
  ('public.zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text)','capture')) t(sig,op)
 LOOP
  d:=pg_get_functiondef(target.sig::regprocedure);
  IF position('pilot_export_' in d)>0 THEN CONTINUE;END IF;
  FOR step IN SELECT * FROM (VALUES
    ('create',$a$k NOT IN('framework','control_id','agent_id'))$a$,
      $b$k NOT IN('framework','control_id','agent_id','pilot_cohort','device_id','endpoint_session_ref')) OR request_value ?| ARRAY['pilot_cohort','device_id','endpoint_session_ref'] AND NOT COALESCE(zasp_authorization80.pilot_export_visible(org_value,workspace_value,environment_value,request_value),false)$b$),
    ('capture',$a$AND NOT j.request?'agent_id' LIMIT 501$a$,$b$AND NOT j.request ?| ARRAY['agent_id','pilot_cohort','device_id'] LIMIT 501$b$),
    ('capture',$a$ELSE '{}'::jsonb END body,$a$,$b$WHEN j.request ?| ARRAY['pilot_cohort','device_id'] THEN jsonb_build_object('pilot_evidence_pack',zasp_authorization80.pilot_export_pack(org_value,workspace_value,environment_value,j.request,stamp)) ELSE '{}'::jsonb END body,$b$)
  ) t(op,anchor,replacement) WHERE op=target.op LOOP
   IF length(d)-length(replace(d,step.anchor,''))<>length(step.anchor) THEN RAISE EXCEPTION 'pilot compliance export predecessor changed'; END IF;
   d:=replace(d,step.anchor,step.replacement);
  END LOOP;
  EXECUTE d;
 END LOOP;
END $pilot_exports$;

-- Explicit extended collection and a fresh data-controls owner authorize a
-- private, static, zero-retention worker upload for one exact archive.
CREATE TABLE IF NOT EXISTS public.zasp_private_addon_uploads (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor text NOT NULL,
 request_key text NOT NULL,grant_id text NOT NULL CHECK(public.zasp_valid_product_id(grant_id)),
 archive_digest text NOT NULL,archive_bytes bigint NOT NULL,expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor,request_key),UNIQUE(grant_id)
);
ALTER TABLE public.zasp_private_addon_uploads OWNER TO zasp_operator;
REVOKE ALL ON public.zasp_private_addon_uploads FROM PUBLIC,zasp_discovery_api;
GRANT SELECT,INSERT,DELETE ON public.zasp_private_addon_uploads TO zasp_discovery_authority;
ALTER TABLE public.zasp_private_addon_uploads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_private_addon_uploads FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS private_addon_grants_authority ON public.zasp_private_addon_uploads;
CREATE POLICY private_addon_grants_authority ON public.zasp_private_addon_uploads TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE OR REPLACE FUNCTION zasp_authorization80.private_addon_upload(o text,w text,e text,actor_value text,request_value text,id_value text,digest_value text,size_value bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $private_addon_upload$
DECLARE proof jsonb;v public.zasp_private_addon_uploads%ROWTYPE;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor_value,'createPrivateAddonUpload','manage_data_controls','environment',e,false,true,true,true);
 IF NOT COALESCE(public.zasp_valid_product_id(id_value) AND request_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND digest_value ~ '^sha256:[a-f0-9]{64}$' AND size_value BETWEEN 1 AND 8388608,false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='private archive binding rejected';END IF;
 IF NOT zasp_authorization80.private_collection_enabled(o,w,e)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='extended collection required';END IF;
 INSERT INTO public.zasp_private_addon_uploads VALUES(o,w,e,actor_value,request_value,id_value,digest_value,size_value,date_trunc('second',clock_timestamp())+interval '5 minutes')
 ON CONFLICT(organization_id,workspace_id,environment_id,actor,request_key) DO NOTHING;
 SELECT * INTO STRICT v FROM public.zasp_private_addon_uploads WHERE (organization_id,workspace_id,environment_id,actor,request_key)=(o,w,e,actor_value,request_value);
 IF (v.archive_digest,v.archive_bytes) IS DISTINCT FROM (digest_value,size_value) OR v.expires_at<=clock_timestamp() THEN RETURN 'null'::jsonb;END IF;
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN jsonb_build_object('id',v.grant_id,'expires_at',v.expires_at);
END $private_addon_upload$;
ALTER FUNCTION zasp_authorization80.private_addon_upload(text,text,text,text,text,text,text,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.private_addon_upload(text,text,text,text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.private_addon_upload(text,text,text,text,text,text,text,bigint) TO zasp_discovery_api;

-- Browser-only retrieval of a findings receipt includes partial observations.
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_scan_get(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_scan_get$
DECLARE proof jsonb; result jsonb;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,NULL,'getAddonScan','view','environment',e,false,true,false,false);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong add-on scope'; END IF;
 SELECT s.receipt||jsonb_build_object('origin',s.report->'origin','ruleset',s.report->'ruleset','findings',s.report->'findings','skipped_count',s.report->'skipped_count','received_at',s.received_at) INTO result FROM public.zasp_addon_scan_receipts s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.scan_id)=(o,w,e,i);
 RETURN COALESCE(result,'null'::jsonb);
END $addon_scan_get$;
ALTER FUNCTION zasp_authorization80.addon_scan_get(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.addon_scan_get(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.addon_scan_get(text,text,text,text) TO zasp_discovery_api;

-- A reviewed content digest can appear in more than one scoped installation.
-- Keep recent positive observations and mark prior complete evidence retained
-- through a partial scan. A new complete partition establishes removal.
CREATE INDEX IF NOT EXISTS zasp_endpoint_partitions_reported_digests ON public.zasp_endpoint_partitions USING gin ((observed->'installations') jsonb_path_ops);
CREATE INDEX IF NOT EXISTS zasp_endpoint_partitions_complete_digests ON public.zasp_endpoint_partitions USING gin ((complete_snapshot->'installations') jsonb_path_ops);
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_installations(o text,w text,e text,i text,n integer,a text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_installations$
DECLARE p jsonb; digest_value text; lookup jsonb; result jsonb;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,NULL,'listAddonVersionInstallations','view','environment',e,false,true,false,false);
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong add-on scope'; END IF;
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR a IS NOT NULL AND (a !~ '^pid_[0-9a-f-]{36}\.[a-f0-9]{64}\.[a-f0-9]{64}$' OR NOT public.zasp_valid_product_id(split_part(a,'.',1))) THEN RAISE invalid_parameter_value; END IF;
 SELECT manifest_digest INTO digest_value FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i); IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 lookup:=jsonb_build_array(jsonb_build_object('manifest_digest',digest_value));
 WITH partitions AS MATERIALIZED (
  SELECT part.*,d.state,d.cohort FROM public.zasp_endpoint_partitions part JOIN public.zasp_endpoint_devices d ON (d.organization_id,d.workspace_id,d.environment_id,d.id)=(part.organization_id,part.workspace_id,part.environment_id,part.device_id)
  WHERE (part.organization_id,part.workspace_id,part.environment_id)=(o,w,e) AND ((part.observed->'installations') @> lookup OR (part.complete_snapshot->'installations') @> lookup)
 ), matches AS (
  SELECT part.*,entry.row->>'installation_id' slot,source.evidence,source.at_time,(source.snapshot->>'snapshot_generation')::bigint seen_gen
  FROM partitions part CROSS JOIN LATERAL (VALUES(part.observed,CASE WHEN (part.observed->>'complete')::boolean THEN 'complete' ELSE 'partial' END,part.observed_at),
   (CASE WHEN NOT (part.observed->>'complete')::boolean THEN part.complete_snapshot END,'last_complete',part.complete_at)) source(snapshot,evidence,at_time)
  CROSS JOIN LATERAL jsonb_array_elements(source.snapshot->'installations') entry(row) WHERE entry.row->>'manifest_digest'=digest_value
 ), unique_slots AS MATERIALIZED (
  SELECT DISTINCT ON(device_id,partition_id,slot) *,device_id||'.'||partition_id||'.'||slot AS page_key FROM matches ORDER BY device_id,partition_id,slot,seen_gen DESC
 ), selected AS MATERIALIZED (SELECT * FROM unique_slots WHERE a IS NULL OR page_key>a ORDER BY page_key LIMIT n+1), page AS (SELECT * FROM selected ORDER BY page_key LIMIT n)
 SELECT CASE WHEN a IS NOT NULL AND NOT EXISTS(SELECT FROM unique_slots WHERE page_key=a) THEN 'null'::jsonb ELSE jsonb_build_object('items',COALESCE((SELECT jsonb_agg(jsonb_build_object('device_id',device_id,'cohort',cohort,'device_state',state,'partition_id',partition_id,'installation_id',slot,'observation',evidence,'generation',seen_gen,'latest_generation',generation,'reported_at',at_time,'latest_reported_at',observed_at) ORDER BY page_key) FROM page),'[]'::jsonb),
 'next_cursor',CASE WHEN (SELECT count(*) FROM selected)>n THEN (SELECT max(page_key) FROM page) END) END INTO result;
 RETURN result;
END $addon_installations$;
ALTER FUNCTION zasp_authorization80.addon_installations(text,text,text,text,integer,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.addon_installations(text,text,text,text,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.addon_installations(text,text,text,text,integer,text) TO zasp_discovery_api;

-- Reviewer declarations, source observations, and decisions have independent
-- lifetimes. A new purpose revision starts a new review queue.
CREATE TABLE IF NOT EXISTS public.zasp_agent_suggestion_scans (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, agent_id text NOT NULL,
 revision bigint NOT NULL, last_scan jsonb NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,agent_id,revision),
 FOREIGN KEY(organization_id,workspace_id,environment_id,agent_id,revision) REFERENCES public.zasp_agent_purpose_versions ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS public.zasp_agent_suggestions (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, agent_id text NOT NULL, revision bigint NOT NULL,
 tool_id text NOT NULL, policy_id text NOT NULL, evidence_ids text[] NOT NULL CHECK(cardinality(evidence_ids) BETWEEN 1 AND 100),
 from_at timestamptz NOT NULL, to_at timestamptz NOT NULL, decision text CHECK(decision IN('request_draft','dismiss')), decided_by text, decided_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,agent_id,revision,tool_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,agent_id,revision) REFERENCES public.zasp_agent_purpose_versions ON DELETE CASCADE,
 CHECK ((decision IS NULL) = (decided_at IS NULL) AND (decision IS NULL) = (decided_by IS NULL))
);
DO $suggestion_rls$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['zasp_agent_suggestions','zasp_agent_suggestion_scans'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',t);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON TABLE public.%I FROM PUBLIC',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='suggestion_authority') THEN
   EXECUTE format('CREATE POLICY suggestion_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $suggestion_rls$;

-- Keep the initial draft's audit link after policy edits, rollouts and deletion.
CREATE INDEX IF NOT EXISTS zasp_suggestion_policy_receipt_audit ON public.zasp_workflow_idempotency
 (organization_id,workspace_id,environment_id,principal_id,(response->>'audit_id')) WHERE operation='createPolicy';

CREATE OR REPLACE FUNCTION zasp_authorization80.agent_suggestions_page(o text,w text,e text,i text,n bigint,cursor_tool text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $suggestions_page$
 WITH page AS (
   SELECT * FROM public.zasp_agent_suggestions s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.agent_id,s.revision)=(o,w,e,i,n)
    AND s.tool_id>cursor_tool ORDER BY s.tool_id LIMIT 101
 ), visible AS (SELECT * FROM page ORDER BY tool_id LIMIT 100)
 SELECT jsonb_build_object('agent_id',i,'purpose_revision',n,'more',(SELECT count(*)>100 FROM page),
  'last_scan',(SELECT last_scan FROM public.zasp_agent_suggestion_scans WHERE (organization_id,workspace_id,environment_id,agent_id,revision)=(o,w,e,i,n)),
  'items',coalesce(jsonb_agg(jsonb_build_object('tool_id',s.tool_id,'policy_id',s.policy_id,'evidence_ids',s.evidence_ids,
   'from',to_char(s.from_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'to',to_char(s.to_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
   'draft_audit_id',receipt.audit_id,'state',CASE WHEN s.decision IS NULL THEN 'suggested' WHEN s.decision='dismiss' THEN 'dismissed'
    WHEN receipt.audit_id IS NOT NULL THEN 'draft_linked' ELSE 'draft_requested' END) ORDER BY s.tool_id),'[]'::jsonb)) FROM visible s
 LEFT JOIN LATERAL (
  SELECT a.audit_id FROM public.zasp_workflow_audit a JOIN public.zasp_workflow_idempotency m
   ON (m.organization_id,m.workspace_id,m.environment_id,m.principal_id,m.operation,m.response->>'audit_id')=(o,w,e,a.principal_id,'createPolicy',a.audit_id)
   WHERE s.decision='request_draft' AND (a.organization_id,a.workspace_id,a.environment_id,a.resource_kind,a.resource_id,a.resource_version,a.operation)
    =(o,w,e,'policy',s.policy_id,1,'createPolicy') AND a.created_at>=s.decided_at
    AND m.response#>>'{body,rollout}'='draft' AND m.response#>>'{body,action}'='block' AND m.response#>>'{body,trigger}'='tool'
    AND m.response#>'{body,conditions}'=jsonb_build_array(jsonb_build_object('field','agent_id','operator','equals','value',i),jsonb_build_object('field','resource','operator','equals','value',s.tool_id))
  LIMIT 1
 ) receipt ON true
$suggestions_page$;
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_suggestions_list(o text,w text,e text,i text,cursor_tool text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $suggestions_list$
DECLARE n bigint; BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'listAgentSuggestions','view','agent',i,true,true,false,false);
 IF cursor_tool IS NULL OR cursor_tool<>'' AND NOT public.zasp_valid_product_id(cursor_tool) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid suggestion cursor'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent')) THEN RETURN 'null'::jsonb; END IF;
 SELECT coalesce(max(revision),0) INTO n FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i);
 RETURN zasp_authorization80.agent_suggestions_page(o,w,e,i,n,cursor_tool);
END $suggestions_list$;
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_suggestions_refresh(o text,w text,e text,a text,i text,n bigint,input jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $suggestions_refresh$
DECLARE purpose public.zasp_agent_purpose_versions%ROWTYPE; candidate record; start_time timestamptz:=(input->>'from')::timestamptz; end_time timestamptz:=(input->>'to')::timestamptz;
 eligible integer:=0; scan jsonb; BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,a,'refreshAgentSuggestions','manage_workflows','agent',i,true,true,false,true);
 IF n IS NULL OR n<1 OR jsonb_typeof(input->'events') IS DISTINCT FROM 'array' OR NOT coalesce((input->>'examined')::int BETWEEN 0 AND 100 AND jsonb_array_length(input->'events')<=(input->>'examined')::int AND start_time<end_time AND end_time-start_time<=interval '30 days' AND end_time<=clock_timestamp() AND jsonb_typeof(input->'truncated')='boolean',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid suggestion scan'; END IF;
 PERFORM id FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT * INTO purpose FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i) ORDER BY revision DESC LIMIT 1;
 IF purpose.revision IS DISTINCT FROM n THEN RETURN '"conflict"'::jsonb; END IF;
 -- Both observations must agree: exact agent/session attribution in the
 -- durable projection and a canonical tool ID from the corresponding search document.
 FOR candidate IN
  SELECT x.tool, array_agg(DISTINCT ev.evidence_id ORDER BY ev.evidence_id) ids, count(DISTINCT ev.event_id)::integer event_count
   FROM jsonb_to_recordset(input->'events') AS x(tool text,event text,session text)
   JOIN public.zasp_runtime_session_events ev ON (ev.organization_id,ev.workspace_id,ev.environment_id,ev.agent_id,ev.session_id,ev.event_id,ev.event_class,ev.confidence)=(o,w,e,i,x.session,x.event,'tool','exact')
   JOIN public.zasp_inventory_entities tool ON (tool.organization_id,tool.workspace_id,tool.environment_id,tool.id,tool.state,tool.product_kind)=(o,w,e,x.tool,'active','tool')
   WHERE ev.event_time>=start_time AND ev.event_time<end_time GROUP BY x.tool ORDER BY x.tool
 LOOP
  eligible:=eligible+candidate.event_count;
  IF NOT(purpose.allowed_tool_ids ? candidate.tool) THEN
   INSERT INTO public.zasp_agent_suggestions(organization_id,workspace_id,environment_id,agent_id,revision,tool_id,policy_id,evidence_ids,from_at,to_at)
   VALUES(o,w,e,i,n,candidate.tool,'policy-purpose-'||encode(public.digest(convert_to(concat_ws('/',o,w,e,i,n,candidate.tool),'UTF8'),'sha256'),'hex'),candidate.ids,start_time,end_time) ON CONFLICT DO NOTHING;
  END IF;
 END LOOP;
 scan:=(input-'events')||jsonb_build_object('eligible',eligible);
 INSERT INTO public.zasp_agent_suggestion_scans VALUES(o,w,e,i,n,scan) ON CONFLICT(organization_id,workspace_id,environment_id,agent_id,revision) DO UPDATE SET last_scan=excluded.last_scan;
 RETURN zasp_authorization80.agent_suggestions_page(o,w,e,i,n,'');
END $suggestions_refresh$;
CREATE OR REPLACE FUNCTION zasp_authorization80.agent_suggestions_review(o text,w text,e text,a text,i text,n bigint,t text,command text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $suggestions_review$
DECLARE current_item public.zasp_agent_suggestions%ROWTYPE; latest bigint; BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,a,'reviewAgentSuggestion','manage_workflows','agent',i,true,true,false,true);
 IF n IS NULL OR n<1 OR command IS NULL OR command NOT IN('request_draft','dismiss') OR NOT public.zasp_valid_product_id(t) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid review decision'; END IF;
 PERFORM id FROM public.zasp_inventory_entities WHERE (organization_id,workspace_id,environment_id,id,state,product_kind)=(o,w,e,i,'active','agent') FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 SELECT max(revision) INTO latest FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i);
 IF latest IS DISTINCT FROM n THEN RETURN '"conflict"'::jsonb; END IF;
 SELECT * INTO current_item FROM public.zasp_agent_suggestions WHERE (organization_id,workspace_id,environment_id,agent_id,revision,tool_id)=(o,w,e,i,n,t) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 IF current_item.decision IS NOT NULL THEN
  IF current_item.decision<>command THEN RETURN '"conflict"'::jsonb; END IF;
 ELSE
  IF command='request_draft' AND EXISTS(SELECT 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(o,w,e,'policy',current_item.policy_id)) THEN RETURN '"conflict"'::jsonb; END IF;
  UPDATE public.zasp_agent_suggestions SET decision=command,decided_by=a,decided_at=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,agent_id,revision,tool_id)=(o,w,e,i,n,t);
 END IF;
 RETURN zasp_authorization80.agent_suggestions_page(o,w,e,i,n,'');
END $suggestions_review$;
DO $suggestion_grants$ DECLARE f text; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.agent_suggestions_page(text,text,text,text,bigint,text)','zasp_authorization80.agent_suggestions_list(text,text,text,text,text)','zasp_authorization80.agent_suggestions_refresh(text,text,text,text,text,bigint,jsonb)','zasp_authorization80.agent_suggestions_review(text,text,text,text,text,bigint,text,text)'] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f::regprocedure);
  IF f NOT LIKE '%agent_suggestions_page%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f::regprocedure); END IF;
 END LOOP;
END $suggestion_grants$;

-- Preserve the manifest's versioned workflow writer, including all prior writers
-- and receipts. Add one transition: an unedited enforced revision can return to
-- its preceding monitor state, using the same scoped CAS and audit transaction.
CREATE OR REPLACE FUNCTION public.zasp_workflow_mutate_v3(mutation text, requested_kind text, requested_id text, requested_organization_id text, requested_workspace_id text, requested_environment_id text, requested_principal_id text, requested_operation text, requested_idempotency_key text, expected_version bigint, requested_intent jsonb, requested_body jsonb, requested_audit_id text, requested_correlation_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
    digest_value bytea;
    prior_digest bytea;
    prior_response jsonb;
    result_body jsonb;
    result_version bigint;
    result_secret_generation bigint;
BEGIN
IF requested_kind='security_agent' THEN PERFORM public.zasp_sa_export_legacy_definition_fence(requested_organization_id,requested_workspace_id,requested_environment_id,requested_id,requested_body);END IF;
    IF mutation NOT IN ('create', 'update', 'delete', 'rotate_secret') OR
       requested_kind NOT IN ('policy', 'integration', 'sensor', 'security_agent', 'security_agent_run', 'security_agent_approval') OR
       length(requested_id) < 1 OR length(requested_id) > 128 OR
       length(requested_idempotency_key) < 16 OR length(requested_idempotency_key) > 128 OR
       jsonb_typeof(requested_intent) <> 'object' OR jsonb_typeof(requested_body) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid workflow mutation';
    END IF;

	PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31), requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_operation, requested_idempotency_key), 0));
    digest_value := digest(convert_to(requested_intent::text, 'UTF8'), 'sha256');
    SELECT "request_digest", "response" INTO prior_digest, prior_response FROM "public"."zasp_workflow_idempotency"
     WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id
       AND "environment_id" = requested_environment_id AND "principal_id" = requested_principal_id
       AND "operation" = requested_operation AND "idempotency_key" = requested_idempotency_key;
    IF FOUND THEN
        IF prior_digest <> digest_value THEN RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'idempotency conflict'; END IF;
        RETURN prior_response || jsonb_build_object('replayed', true);
    END IF;

    IF mutation = 'create' THEN
        IF requested_kind = 'policy' AND (requested_operation <> 'createPolicy' OR requested_body ->> 'rollout' <> 'draft') THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'policy must be created as draft';
        END IF;
        INSERT INTO "public"."zasp_workflow_records" ("organization_id", "workspace_id", "environment_id", "kind", "id", "body")
        VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_kind, requested_id, requested_body)
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'update' THEN
        UPDATE "public"."zasp_workflow_records" AS record
           SET "body" = CASE WHEN requested_kind = 'policy' THEN requested_body - '_target_environment_id' ELSE requested_body END,
               "version" = record."version" + 1,
               "updated_at" = transaction_timestamp()
         WHERE record."organization_id" = requested_organization_id AND record."workspace_id" = requested_workspace_id AND record."environment_id" = requested_environment_id
           AND record."kind" = requested_kind AND record."id" = requested_id AND record."deleted_at" IS NULL AND record."version" = expected_version
           AND (requested_kind <> 'policy' OR
                requested_operation = 'updatePolicy' AND requested_body ->> 'rollout' = record."body" ->> 'rollout' OR
                requested_operation = 'rolloutPolicy' AND requested_body ->> '_target_environment_id' = requested_environment_id AND
                    ((record."body" ->> 'rollout' = 'draft' AND requested_body ->> 'rollout' = 'monitor') OR
                     (record."body" ->> 'rollout' = 'monitor' AND requested_body ->> 'rollout' = 'enforced') OR
                     (record."body" ->> 'rollout' = 'enforced' AND requested_body ->> 'rollout' = 'monitor'
                      AND requested_body - ARRAY['rollout','_target_environment_id'] = record."body" - 'rollout'
                      AND EXISTS (SELECT 1 FROM public.zasp_workflow_audit h
                       WHERE (h.organization_id,h.workspace_id,h.environment_id,h.resource_kind,h.resource_id,h.resource_version,h.operation)
                        =(requested_organization_id,requested_workspace_id,requested_environment_id,'policy',requested_id,expected_version,'rolloutPolicy')))) OR
                requested_operation = 'disablePolicy' AND requested_body ->> '_target_environment_id' = requested_environment_id AND
                    record."body" ->> 'rollout' IN ('monitor', 'enforced') AND requested_body ->> 'rollout' = 'disabled')
        RETURNING record."body", record."version", record."secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'delete' THEN
        UPDATE "public"."zasp_workflow_records" SET "deleted_at" = transaction_timestamp(), "version" = "version" + 1, "updated_at" = transaction_timestamp()
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
           AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL AND "version" = expected_version
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    ELSIF mutation = 'rotate_secret' THEN
        UPDATE "public"."zasp_workflow_records" SET "secret_generation" = "secret_generation" + 1, "version" = "version" + 1, "updated_at" = transaction_timestamp()
         WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id
           AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL AND "version" = expected_version
        RETURNING "body", "version", "secret_generation" INTO result_body, result_version, result_secret_generation;
    END IF;

    IF result_body IS NULL THEN
        IF EXISTS (SELECT 1 FROM "public"."zasp_workflow_records" WHERE "organization_id" = requested_organization_id AND "workspace_id" = requested_workspace_id AND "environment_id" = requested_environment_id AND "kind" = requested_kind AND "id" = requested_id AND "deleted_at" IS NULL) THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'workflow version conflict';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'workflow record missing';
    END IF;

    prior_response := jsonb_build_object('body', result_body, 'version', result_version, 'secret_generation', result_secret_generation, 'audit_id', requested_audit_id, 'correlation_id', requested_correlation_id, 'replayed', false);
    INSERT INTO "public"."zasp_workflow_audit" ("organization_id", "workspace_id", "environment_id", "audit_id", "correlation_id", "principal_id", "operation", "resource_kind", "resource_id", "resource_version")
    VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_audit_id, requested_correlation_id, requested_principal_id, requested_operation, requested_kind, requested_id, result_version);
    INSERT INTO "public"."zasp_workflow_idempotency" ("organization_id", "workspace_id", "environment_id", "principal_id", "operation", "idempotency_key", "request_digest", "response")
    VALUES (requested_organization_id, requested_workspace_id, requested_environment_id, requested_principal_id, requested_operation, requested_idempotency_key, digest_value, prior_response);
    RETURN prior_response;
END;
$function$;

-- Each profile is one separately issued machine token, registered by a fresh
-- administrator with its locally generated signing public key.
DO $browser_permission$
DECLARE f regprocedure; d text; n integer:=0;
 a constant text:=$a$'sync_endpoint','use_gateway','view',$a$;
 b constant text:=$b$'sync_endpoint','use_gateway','view','report_browser_usage',$b$;
BEGIN
 FOR f IN SELECT p.oid FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_identity'::regnamespace AND p.proname='create_pat' LOOP
  d:=pg_get_functiondef(f); IF position(b IN d)>0 THEN n:=n+1;
  ELSIF length(d)-length(replace(d,a,''))=length(a) THEN EXECUTE replace(d,a,b); n:=n+1; END IF;
 END LOOP;
 IF n=0 THEN RAISE EXCEPTION 'unrecognized browser PAT issuance contract'; END IF;
END $browser_permission$;

CREATE TABLE IF NOT EXISTS public.zasp_browser_profiles(
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, credential_id text NOT NULL,
 public_key text NOT NULL, origins jsonb NOT NULL, created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz, last_sync timestamptz, last_nonce text, last_digest text, last_observation date,
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id)
);
CREATE TABLE IF NOT EXISTS public.zasp_browser_origin_days(
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL, credential_id text NOT NULL,
 origin text NOT NULL CHECK(origin IN('https://claude.ai','https://chatgpt.com')), day date NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,credential_id,origin,day),
 FOREIGN KEY(organization_id,workspace_id,environment_id,credential_id) REFERENCES public.zasp_browser_profiles(organization_id,workspace_id,environment_id,credential_id)
);
DO $browser_rls$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['zasp_browser_profiles','zasp_browser_origin_days'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',t);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',t);
  IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='browser_profile_authority') THEN
   EXECUTE format('CREATE POLICY browser_profile_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $browser_rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.browser_profile(o text,w text,e text,actor text,cred text,v jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $profile$
DECLARE p jsonb; op text; row public.zasp_browser_profiles%ROWTYPE; nowval timestamptz:=clock_timestamp();
 exp timestamptz; revoked timestamptz; state text; machine boolean; item jsonb; latest date;
BEGIN
 op:=zasp_authorization80.context()->>'operation_id'; machine:=op='recordBrowserOriginDays';
 IF op IS NULL OR op NOT IN('recordBrowserOriginDays','getBrowserProfile','registerBrowserProfile','retireBrowserProfile') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='browser profile operation required'; END IF;
 p:=zasp_authorization80.product_request(o,w,e,actor,op,CASE WHEN machine THEN 'report_browser_usage' ELSE 'manage_api_tokens' END,'environment',e,false,NOT machine,
 op IN('registerBrowserProfile','retireBrowserProfile'),op IN('registerBrowserProfile','retireBrowserProfile') OR (machine AND NOT v?'inspect'));
 IF p#>>'{path_parameters,id}' IS DISTINCT FROM cred OR NOT public.zasp_valid_product_id(cred) OR machine AND
 (p->>'credential_kind' IS DISTINCT FROM '2' OR p->>'credential_id' IS DISTINCT FROM cred OR p->'pat_ceiling' IS DISTINCT FROM '["report_browser_usage"]'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='browser credential binding required'; END IF;
 SELECT expires_at,revoked_at INTO exp,revoked FROM public.zasp_product_api_tokens
 WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,cred) AND permissions='["report_browser_usage"]'::jsonb FOR SHARE;
 IF NOT FOUND OR (machine OR op='registerBrowserProfile') AND (revoked IS NOT NULL OR exp<=nowval) THEN RETURN 'null'; END IF;
 IF op='registerBrowserProfile' THEN
  IF jsonb_typeof(v->'origins') IS DISTINCT FROM 'array' OR NOT v->'origins' <@ '["https://claude.ai","https://chatgpt.com"]'::jsonb OR jsonb_array_length(v->'origins') NOT BETWEEN 1 AND 2 OR
   v->>'public_key' IS NULL OR octet_length(decode(v->>'public_key','base64'))<>65 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid browser profile registration'; END IF;
  INSERT INTO public.zasp_browser_profiles(organization_id,workspace_id,environment_id,credential_id,public_key,origins,created_by)
   VALUES(o,w,e,cred,v->>'public_key',v->'origins',actor) ON CONFLICT DO NOTHING;
 END IF;
 SELECT * INTO row FROM public.zasp_browser_profiles WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,cred) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'; END IF;
 IF op='registerBrowserProfile' AND (row.public_key<>v->>'public_key' OR row.origins<>v->'origins' OR row.retired_at IS NOT NULL) THEN RETURN '"conflict"'; END IF;
 IF machine THEN
  IF row.retired_at IS NOT NULL THEN RETURN 'null'; END IF;
  IF v='{"inspect":true}' THEN RETURN jsonb_build_object('public_key',row.public_key); END IF;
  IF v->>'public_key' IS DISTINCT FROM row.public_key OR v->>'nonce' IS NULL OR v->>'nonce' !~ '^[0-9a-f]{32}$' OR v->>'digest' IS NULL OR v->>'digest' !~ '^[0-9a-f]{64}$' OR
   jsonb_typeof(v->'days') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'days')>60 OR NOT COALESCE((v->>'issued_at')::bigint BETWEEN floor(extract(epoch FROM nowval))::bigint-120 AND floor(extract(epoch FROM nowval))::bigint+30,false) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid browser observation'; END IF;
  -- A repeated signed message cannot refresh health after its original delivery.
  IF row.last_nonce=v->>'nonce' THEN
   IF row.last_digest IS DISTINCT FROM v->>'digest' THEN RETURN '"conflict"'; END IF;
  ELSE
   IF row.last_sync IS NOT NULL AND to_timestamp((v->>'issued_at')::bigint)<date_trunc('second',row.last_sync) THEN RETURN '"stale"'; END IF;
   -- Persist the signed timestamp instead of server receipt time to prevent
   -- replay of older valid reports from extending profile freshness.
   FOR item IN SELECT value FROM jsonb_array_elements(v->'days') LOOP
    IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>2 OR
     NOT COALESCE(row.origins ? (item->>'origin'),false) OR item->>'day' IS NULL OR item->>'day' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' OR (item->>'day')::date NOT BETWEEN (nowval AT TIME ZONE 'UTC')::date-29 AND (nowval AT TIME ZONE 'UTC')::date THEN RETURN '"forbidden"'; END IF;
   END LOOP;
   DELETE FROM public.zasp_browser_origin_days WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,cred) AND day<(nowval AT TIME ZONE 'UTC')::date-29;
   FOR item IN SELECT value FROM jsonb_array_elements(v->'days') LOOP
    INSERT INTO public.zasp_browser_origin_days VALUES(o,w,e,cred,item->>'origin',(item->>'day')::date) ON CONFLICT DO NOTHING;
    latest:=greatest(latest,(item->>'day')::date);
   END LOOP;
   UPDATE public.zasp_browser_profiles SET last_sync=to_timestamp((v->>'issued_at')::bigint),last_nonce=v->>'nonce',last_digest=v->>'digest',last_observation=greatest(last_observation,latest)
    WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,cred);
  END IF;
  PERFORM zasp_authorization80.product_settled(p);
  RETURN jsonb_build_object('credential_id',cred,'environment_id',e,'accepted',true);
 END IF;
 IF op='retireBrowserProfile' AND row.retired_at IS NULL THEN
  DELETE FROM public.zasp_browser_origin_days WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,cred);
  UPDATE public.zasp_browser_profiles SET retired_at=nowval,last_observation=NULL WHERE (organization_id,workspace_id,environment_id,credential_id)=(o,w,e,cred) RETURNING * INTO row;
 END IF;
 state:=CASE WHEN row.retired_at IS NOT NULL OR revoked IS NOT NULL THEN 'revoked' WHEN exp<=nowval THEN 'expired' WHEN row.last_sync IS NULL THEN 'awaiting_profile' WHEN row.last_sync<nowval-interval '2 hours' THEN 'stale' ELSE 'reporting' END;
 IF op<>'getBrowserProfile' THEN PERFORM zasp_authorization80.product_settled(p); END IF;
 RETURN jsonb_build_object('credential_id',cred,'environment_id',e,'origins',row.origins,'state',state,'expires_at',exp,'last_sync',row.last_sync,'last_observation',row.last_observation,
  'observations',COALESCE((SELECT jsonb_agg(jsonb_build_object('origin',d.origin,'day',d.day) ORDER BY d.day DESC,d.origin)
   FROM public.zasp_browser_origin_days d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.credential_id)=(o,w,e,cred) AND d.day>=(nowval AT TIME ZONE 'UTC')::date-29),'[]'::jsonb));
END $profile$;
ALTER FUNCTION zasp_authorization80.browser_profile(text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.browser_profile(text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.browser_profile(text,text,text,text,text,jsonb) TO zasp_discovery_api;

-- Retain independently submitted findings from a private worker. No ZIP,
-- paths, arguments or source content enters the registry or its retry keys.
ALTER TABLE public.zasp_addon_versions DROP CONSTRAINT IF EXISTS zasp_addon_versions_origin_check;
ALTER TABLE public.zasp_addon_versions ADD CONSTRAINT zasp_addon_versions_origin_check CHECK(origin IN('ci','local','private_worker'));
CREATE TABLE IF NOT EXISTS public.zasp_private_addon_reporters(
 grant_id text PRIMARY KEY REFERENCES public.zasp_private_addon_uploads(grant_id),
 credential_id text NOT NULL CHECK(credential_id='' OR public.zasp_valid_product_id(credential_id))
);
ALTER TABLE public.zasp_private_addon_reporters OWNER TO zasp_operator;
REVOKE ALL ON public.zasp_private_addon_reporters FROM PUBLIC,zasp_discovery_api;
GRANT SELECT,INSERT ON public.zasp_private_addon_reporters TO zasp_discovery_authority;
ALTER TABLE public.zasp_private_addon_reporters ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_private_addon_reporters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS private_reporter_authority ON public.zasp_private_addon_reporters;
CREATE POLICY private_reporter_authority ON public.zasp_private_addon_reporters TO zasp_discovery_authority USING(true) WITH CHECK(true);

CREATE OR REPLACE FUNCTION zasp_authorization80.private_addon_upload_with_reporter(o text,w text,e text,actor_value text,request_value text,id_value text,digest_value text,size_value bigint,reporter text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $private_reporter$
DECLARE receipt jsonb; chosen text;
BEGIN
 receipt:=zasp_authorization80.private_addon_upload(o,w,e,actor_value,request_value,id_value,digest_value,size_value);
 IF receipt IS NULL OR receipt='null'::jsonb THEN RETURN receipt; END IF;
 IF reporter IS NULL OR (reporter<>'' AND NOT EXISTS(SELECT 1 FROM public.zasp_product_api_tokens t
  WHERE (t.organization_id,t.workspace_id,t.environment_id,t.id)=(o,w,e,reporter) AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp() AND t.permissions='["submit_addon_scans"]'::jsonb))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='private reporter must be a live dedicated findings credential';END IF;
 INSERT INTO public.zasp_private_addon_reporters VALUES(receipt->>'id',reporter) ON CONFLICT DO NOTHING;
 SELECT credential_id INTO STRICT chosen FROM public.zasp_private_addon_reporters WHERE grant_id=receipt->>'id';
 IF chosen IS DISTINCT FROM reporter THEN RETURN 'null'::jsonb; END IF;
 RETURN receipt;
END $private_reporter$;
ALTER FUNCTION zasp_authorization80.private_addon_upload_with_reporter(text,text,text,text,text,text,text,bigint,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.private_addon_upload_with_reporter(text,text,text,text,text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.private_addon_upload_with_reporter(text,text,text,text,text,text,text,bigint,text) TO zasp_discovery_api;
REVOKE EXECUTE ON FUNCTION zasp_authorization80.private_addon_upload(text,text,text,text,text,text,text,bigint) FROM zasp_discovery_api;

-- Return only the collection eligibility bit to the authority that already
-- admitted an Environment request. Keep data-controls tables private.
CREATE OR REPLACE FUNCTION zasp_authorization80.private_collection_enabled(o text,w text,e text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $private_collection$
 SELECT EXISTS(SELECT FROM public.zasp_data_controls c JOIN public.zasp_environments a ON
 (a.organization_id,a.workspace_id,a.id,a.environment_class)=(c.organization_id,c.workspace_id,c.environment_id,c.environment_class)
 WHERE (c.organization_id,c.workspace_id,c.environment_id)=(o,w,e) AND c.collection_mode='extended' AND a.environment_class IN ('development','test','staging'))
$private_collection$;
ALTER FUNCTION zasp_authorization80.private_collection_enabled(text,text,text) OWNER TO zasp_operator;
REVOKE ALL ON FUNCTION zasp_authorization80.private_collection_enabled(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.private_collection_enabled(text,text,text) TO zasp_discovery_authority;

-- Each admitted observation is an immutable graph input. The facts remain
-- queryable in PostgreSQL while the graph is down or its queue is replayed.
CREATE TABLE IF NOT EXISTS public.zasp_action_graph_evidence (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 evidence_id text NOT NULL, fact jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(), available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text, projected_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,evidence_id),
 CHECK(public.zasp_valid_product_id(evidence_id))
);
ALTER TABLE public.zasp_action_graph_evidence OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_action_graph_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_action_graph_evidence FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_action_graph_evidence FROM PUBLIC;
DO $graph_rls$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename='zasp_action_graph_evidence' AND policyname='action_graph_authority') THEN
  CREATE POLICY action_graph_authority ON public.zasp_action_graph_evidence TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $graph_rls$;
CREATE INDEX IF NOT EXISTS zasp_action_graph_pending ON public.zasp_action_graph_evidence(available_at,recorded_at,evidence_id) WHERE projected_at IS NULL;

CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_action_fact(x public.zasp_endpoint_observations) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $endpoint_fact$
 SELECT jsonb_build_object('source','signed_endpoint','event_type','hook_decision','evidence_id',
  public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'signed_hook_receipt',concat_ws('/',x.device_id,x.credential_generation,x.action_id)),
  'subject_id',x.device_id,'observed_at',to_char((x.observation->>'observed_at')::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
  'verdict',x.observation->>'verdict','session_id',public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'device_local_session',
  concat_ws('/',x.device_id,x.credential_generation,x.observation->>'local_uid',x.observation->>'session_ref')))
$endpoint_fact$;

CREATE OR REPLACE FUNCTION zasp_authorization80.workload_action_facts(x public.zasp_workload_actions) RETURNS SETOF jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $workload_facts$
 WITH base AS (SELECT jsonb_build_object('source','authenticated_workload','subject_id',x.credential_id) ||
  COALESCE((SELECT jsonb_build_object('agent_id',b.agent_id,'session_id',b.session_id) FROM public.zasp_workload_bindings b
   WHERE (b.organization_id,b.workspace_id,b.environment_id,b.credential_id)=(x.organization_id,x.workspace_id,x.environment_id,x.credential_id)
   AND b.created_at<=x.created_at),'{}'::jsonb) AS doc)
 SELECT doc||jsonb_build_object('event_type','action_decision','evidence_id',x.receipt->>'decision_id','verdict',x.receipt->>'verdict',
  'observed_at',to_char(x.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM base
 UNION ALL SELECT doc||jsonb_build_object('event_type','action_outcome','decision_id',x.receipt->>'decision_id','verdict',x.outcome->>'status',
  'evidence_id',public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'workload_outcome',x.receipt->>'decision_id'),
  'observed_at',to_char(x.observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM base WHERE x.outcome IS NOT NULL
$workload_facts$;
CREATE OR REPLACE FUNCTION zasp_authorization80.capture_action_graph() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $graph_capture$
BEGIN
 IF TG_TABLE_NAME='zasp_endpoint_observations' THEN
  INSERT INTO public.zasp_action_graph_evidence(organization_id,workspace_id,environment_id,evidence_id,fact)
  SELECT NEW.organization_id,NEW.workspace_id,NEW.environment_id,f->>'evidence_id',f FROM zasp_authorization80.endpoint_action_fact(NEW) f ON CONFLICT DO NOTHING;
 ELSE
  INSERT INTO public.zasp_action_graph_evidence(organization_id,workspace_id,environment_id,evidence_id,fact)
  SELECT NEW.organization_id,NEW.workspace_id,NEW.environment_id,f->>'evidence_id',f FROM zasp_authorization80.workload_action_facts(NEW) f ON CONFLICT DO NOTHING;
 END IF;
 RETURN NULL;
END $graph_capture$;
CREATE OR REPLACE TRIGGER zasp_graph_hook_receipt AFTER INSERT ON public.zasp_endpoint_observations FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.capture_action_graph();
CREATE OR REPLACE TRIGGER zasp_graph_workload_receipt AFTER INSERT OR UPDATE OF outcome ON public.zasp_workload_actions FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.capture_action_graph();

-- Retained source rows pre-dating this change follow the same path. A later
-- agent binding cannot confer retroactive attribution on a workload receipt.
INSERT INTO public.zasp_action_graph_evidence(organization_id,workspace_id,environment_id,evidence_id,fact)
SELECT x.organization_id,x.workspace_id,x.environment_id,f->>'evidence_id',f FROM public.zasp_endpoint_observations x
 CROSS JOIN LATERAL zasp_authorization80.endpoint_action_fact(x) f ON CONFLICT DO NOTHING;
INSERT INTO public.zasp_action_graph_evidence(organization_id,workspace_id,environment_id,evidence_id,fact)
SELECT x.organization_id,x.workspace_id,x.environment_id,f->>'evidence_id',f FROM public.zasp_workload_actions x
 CROSS JOIN LATERAL zasp_authorization80.workload_action_facts(x) f ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION public.zasp_action_graph_claim(token text,lim int,seconds int) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $graph_claim$
DECLARE result jsonb;
BEGIN
 IF NOT public.zasp_execution_principal_ready('zasp_projection_graph_worker') THEN RAISE insufficient_privilege; END IF;
 IF NOT COALESCE(token~'^[0-9a-f]{32}$' AND lim BETWEEN 1 AND 50 AND seconds BETWEEN 3 AND 600,false) THEN RAISE invalid_parameter_value; END IF;
 WITH candidates AS (SELECT q.organization_id,q.workspace_id,q.environment_id,q.evidence_id FROM public.zasp_action_graph_evidence q
  WHERE q.projected_at IS NULL AND q.available_at<=clock_timestamp() ORDER BY q.available_at,q.recorded_at,q.evidence_id LIMIT lim FOR UPDATE SKIP LOCKED),
 leased AS (UPDATE public.zasp_action_graph_evidence q SET available_at=clock_timestamp()+make_interval(secs=>seconds),lease_token=token FROM candidates c
  WHERE (q.organization_id,q.workspace_id,q.environment_id,q.evidence_id)=(c.organization_id,c.workspace_id,c.environment_id,c.evidence_id)
  RETURNING q.organization_id,q.workspace_id,q.environment_id,q.fact)
 SELECT COALESCE(jsonb_agg(to_jsonb(leased) ORDER BY organization_id,workspace_id,environment_id,fact->>'evidence_id'),'[]'::jsonb) INTO result FROM leased;
 RETURN result;
END $graph_claim$;
CREATE OR REPLACE FUNCTION public.zasp_action_graph_ack(o text,w text,e text,id text,token text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $graph_ack$
BEGIN
 IF NOT public.zasp_execution_principal_ready('zasp_projection_graph_worker') THEN RAISE insufficient_privilege; END IF;
 UPDATE public.zasp_action_graph_evidence q SET projected_at=clock_timestamp(),lease_token=NULL
 WHERE (q.organization_id,q.workspace_id,q.environment_id,q.evidence_id,q.lease_token)=(o,w,e,id,token) AND q.projected_at IS NULL AND q.available_at>clock_timestamp();
 RETURN to_jsonb(FOUND);
END $graph_ack$;

-- Rebuild one Environment on operator request. A stale worker completion
-- cannot acknowledge an item after this invalidates its lease.
CREATE OR REPLACE FUNCTION public.zasp_action_graph_rebuild(o text,w text,e text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $graph_rebuild$
DECLARE n bigint;
BEGIN
 IF session_user<>'zasp_operator' THEN RAISE insufficient_privilege; END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e),false) THEN RAISE invalid_parameter_value; END IF;
 UPDATE public.zasp_action_graph_evidence SET projected_at=NULL,lease_token=NULL,available_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id)=(o,w,e);
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n;
END $graph_rebuild$;
DO $graph_grants$ DECLARE f text; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.endpoint_action_fact(public.zasp_endpoint_observations)','zasp_authorization80.workload_action_facts(public.zasp_workload_actions)','zasp_authorization80.capture_action_graph()','public.zasp_action_graph_claim(text,integer,integer)','public.zasp_action_graph_ack(text,text,text,text,text)','public.zasp_action_graph_rebuild(text,text,text)'] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f::regprocedure);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f::regprocedure);
  IF f LIKE '%_claim(%' OR f LIKE '%_ack(%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_projection_graph_worker',f::regprocedure); END IF;
 END LOOP;
END $graph_grants$;
