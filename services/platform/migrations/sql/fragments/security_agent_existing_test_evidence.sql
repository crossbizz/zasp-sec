-- Private read authority only. A future guarded reconciler wrapper must hold
-- the exact link claim/lease and recheck it at settlement. No worker grant.
-- STABLE reads one statement snapshot without acquiring inverse historical
-- run/definition locks. The caller cannot select a different test run/attempt.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_evidence_snapshot(o text,w text,e text,r text,s text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $evidence$
DECLARE link_row public.zasp_security_agent_test_links%ROWTYPE;run_row public.zasp_red_team_runs%ROWTYPE;
 attempt_row public.zasp_red_team_attempts%ROWTYPE;candidate record;value jsonb;receipt jsonb;observations_value jsonb;
 before_value jsonb:='null'::jsonb;after_value jsonb:='null'::jsonb;unknown_value boolean;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(s),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test evidence scope rejected';END IF;
 SELECT * INTO link_row FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test evidence link unavailable';END IF;
 FOR candidate IN SELECT 'after'::text side,link_row.test_run_id id,NULL::integer attempt
  UNION ALL SELECT 'before',link_row.baseline->>'run_id',(link_row.baseline->>'attempt')::integer WHERE link_row.baseline IS NOT NULL LOOP
  SELECT * INTO run_row FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)=(o,w,e,candidate.id,link_row.test_definition_id,link_row.test_definition_version);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test evidence run changed';END IF;
  value:=jsonb_build_object('run_id',run_row.run_id,'state',run_row.state,'attempt',run_row.attempt,'input_digest',encode(run_row.input_digest,'hex'),'verdict',run_row.verdict,'error_code',run_row.error_code,'completed_at',to_char(run_row.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_artifact',NULL,'output_artifact',NULL);
  IF candidate.side='before' AND (run_row.state<>'complete' OR run_row.verdict IS DISTINCT FROM 'fail' OR run_row.attempt IS DISTINCT FROM candidate.attempt OR run_row.completed_at IS NULL OR run_row.completed_at>=link_row.created_at) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test baseline completion changed';END IF;
  IF run_row.state='complete' THEN
   SELECT * INTO attempt_row FROM public.zasp_red_team_attempts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,run_row.run_id,run_row.attempt);
   IF NOT FOUND OR run_row.completed_at IS NULL OR run_row.verdict IS NULL
    OR (attempt_row.input_digest,attempt_row.verdict,attempt_row.error_code,attempt_row.completed_at,attempt_row.evidence_reference,attempt_row.evidence_key,attempt_row.evidence_version_id,attempt_row.evidence_checksum,attempt_row.evidence_size)
     IS DISTINCT FROM (run_row.input_digest,run_row.verdict,run_row.error_code,run_row.completed_at,run_row.evidence_reference,run_row.evidence_key,run_row.evidence_version_id,run_row.evidence_checksum,run_row.evidence_size)
    OR NOT public.zasp_red_team_valid_input_artifact(o,w,e,attempt_row.input_artifact)
    OR attempt_row.evidence_checksum=decode(repeat('00',32),'hex')
    OR NOT public.zasp_discovery_s3_object_reference(attempt_row.evidence_reference)
    OR attempt_row.evidence_key IS DISTINCT FROM 'organizations/'||o||'/workspaces/'||w||'/environments/'||e||'/artifacts/'||run_row.run_id
    OR substring(attempt_row.evidence_reference FROM '^s3://[^/]+/(.+)$') IS DISTINCT FROM attempt_row.evidence_key
    OR length(attempt_row.evidence_version_id) NOT BETWEEN 1 AND 512 OR attempt_row.evidence_version_id~'[[:space:][:cntrl:]]'
    OR attempt_row.input_artifact->>'reference'=attempt_row.evidence_reference THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test evidence attempt changed';END IF;
   receipt:=jsonb_build_object('reference',attempt_row.evidence_reference,'key',attempt_row.evidence_key,'version_id',attempt_row.evidence_version_id,'sha256',encode(attempt_row.evidence_checksum,'hex'),'size_bytes',attempt_row.evidence_size);
   IF candidate.side='before' AND link_row.baseline IS DISTINCT FROM jsonb_build_object('schema_version','security-agent-test-baseline-v1','run_id',attempt_row.run_id,'attempt',attempt_row.attempt,'input_digest',encode(attempt_row.input_digest,'hex'),'completed_at',to_char(attempt_row.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'input_artifact',attempt_row.input_artifact,'output_artifact',receipt) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test baseline receipt changed';END IF;
   value:=value||jsonb_build_object('input_artifact',attempt_row.input_artifact,'output_artifact',receipt);
  END IF;
  IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(o,w,e,run_row.run_id)
   AND (j.attempt IS DISTINCT FROM run_row.attempt OR j.input_digest IS DISTINCT FROM run_row.input_digest OR NOT link_row.test_categories ? j.category
    OR (j.target_resolution->'comparison'->>'organization_id',j.target_resolution->'comparison'->>'workspace_id',j.target_resolution->'comparison'->>'environment_id',j.target_resolution->'comparison'->>'test_definition_id',j.target_resolution->'comparison'->>'test_definition_version',j.target_resolution->'comparison'->>'target_id',j.target_resolution->'comparison'->>'target_kind')
     IS DISTINCT FROM (o,w,e,link_row.test_definition_id,link_row.test_definition_version::text,link_row.target_id,link_row.target_kind)
    OR j.target_resolution->'comparison'->'categories' IS DISTINCT FROM link_row.test_categories)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test evidence invocation changed';END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object('schema_version','red-team-linked-observation-v1','run_id',j.test_run_id,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'target_comparison',j.target_resolution->'comparison','observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected)) ORDER BY j.category),'[]'::jsonb)
   INTO observations_value FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.attempt,j.input_digest,j.state,j.http_status)=(o,w,e,run_row.run_id,run_row.attempt,run_row.input_digest,'completed',200);
  SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id,j.state)=(o,w,e,run_row.run_id,'started')) INTO unknown_value;
  value:=value||jsonb_build_object('observations',observations_value,'outcome_unknown',unknown_value);
  IF candidate.side='after' THEN after_value:=value;ELSE before_value:=value;END IF;
 END LOOP;
 RETURN jsonb_build_object('schema_version','security-agent-test-evidence-snapshot-v1','organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,
  'definition_id',link_row.test_definition_id,'definition_version',link_row.test_definition_version,'target_id',link_row.target_id,'target_kind',link_row.target_kind,'categories',link_row.test_categories,'before',before_value,'after',after_value);
END
$evidence$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_evidence_snapshot(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_evidence_snapshot(text,text,text,text,text) FROM PUBLIC;
