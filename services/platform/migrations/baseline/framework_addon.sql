-- Older clients retain their original closed six-rule report contract.
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
  OR report->>'manifest_method' IS DISTINCT FROM 'addon-manifest.v1' OR NOT COALESCE(report->>'ruleset' IN('zasp-static.v1','zasp-static.v2'),false)
  OR NOT COALESCE(report->>'origin' IN('ci','local') AND report->>'completeness' IN('complete','partial'),false)
  OR jsonb_typeof(report->'skipped_count') IS DISTINCT FROM 'number' OR report->>'skipped_count' !~ '^(0|[1-9][0-9]{0,5}|1000000)$'
  OR jsonb_typeof(report->'findings') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF report->>'completeness'='complete' AND (NOT COALESCE(report->>'manifest_digest' ~ '^sha256:[a-f0-9]{64}$',false) OR report->>'skipped_count'<>'0')
  OR report->>'completeness'='partial' AND report->'manifest_digest' IS DISTINCT FROM 'null'::jsonb OR jsonb_array_length(report->'findings')>10 THEN RETURN false; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(report->'findings') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT item ?& ARRAY['rule_id','count'] OR (SELECT count(*) FROM jsonb_object_keys(item))<>2
   OR NOT COALESCE(item->>'rule_id' IN('dependency.unpinned','script.shell_execution','script.network_access','instruction.hidden_text','mcp.unpinned_launcher','mcp.remote_endpoint') OR (report->>'ruleset'='zasp-static.v2' AND item->>'rule_id' IN('instruction.override','script.credential_path_access','script.remote_exec_pipe','mcp.unpinned_exec')),false)
   OR (item->>'rule_id')=ANY(seen) OR jsonb_typeof(item->'count') IS DISTINCT FROM 'number' OR item->>'count' !~ '^([1-9][0-9]{0,5}|1000000)$' THEN RETURN false; END IF;
  seen:=array_append(seen,item->>'rule_id');
 END LOOP;
 RETURN true;
END $addon_valid$;

-- Keep findings immutable for each scoped origin and ruleset of an exact manifest.
-- CREATE OR REPLACE preserves the established function owner and execute grants.
CREATE OR REPLACE FUNCTION zasp_authorization80.addon_scan_submit(o text,w text,e text,actor_value text,key_value text,scan_value text,version_candidate text,report_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $addon_submit$
DECLARE proof jsonb; credential text; version_value text; receipt_value jsonb; prior public.zasp_addon_scan_receipts%ROWTYPE;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,actor_value,'submitAddonScan','submit_addon_scans','environment',e,false,false,false,true);
 credential:=proof->>'credential_id';
 -- Recheck the human's testing grant at use, including exact replays. Native
 -- automation tokens keep their separately administered scope and origin.
 IF EXISTS(SELECT FROM zasp_authorization80_identity.cli_authorizations g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.principal_id,g.credential_id)=(o,w,e,actor_value,credential))
  AND (NOT zasp_authorization80_identity.cli_submitter_active(o,w,e,actor_value) OR report_value->>'origin' IS DISTINCT FROM 'local' OR report_value?'private_upload') THEN
  RETURN '"forbidden"'::jsonb;
 END IF;
 IF proof->>'credential_kind' IS DISTINCT FROM '2' OR proof->'pat_ceiling' IS DISTINCT FROM '["submit_addon_scans"]'::jsonb OR credential IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='restricted submission credential required'; END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(scan_value) AND public.zasp_valid_product_id(version_candidate) AND key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND zasp_authorization80.addon_report_valid(report_value,e),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid findings report'; END IF;
 -- Serialize only this scoped retry key. Concurrent distinct scans can share a version.
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,credential,key_value)::text,0));
 SELECT * INTO prior FROM public.zasp_addon_scan_receipts WHERE (organization_id,workspace_id,environment_id,credential_id,request_key)=(o,w,e,credential,key_value);
 IF FOUND AND prior.report IS DISTINCT FROM report_value THEN RETURN '"conflict"'::jsonb; END IF;
 IF prior.scan_id IS NULL AND report_value->>'origin'='private_worker' AND NOT EXISTS(
  SELECT 1 FROM public.zasp_private_addon_uploads g JOIN public.zasp_private_addon_reporters b ON b.grant_id=g.grant_id
  WHERE (g.organization_id,g.workspace_id,g.environment_id,g.grant_id)=(o,w,e,report_value#>>'{private_upload,id}')
   AND b.credential_id=credential AND key_value='private-upload-'||g.grant_id
   AND (g.archive_digest,g.archive_bytes)=(report_value#>>'{private_upload,archive_digest}',(report_value#>>'{private_upload,archive_bytes}')::bigint)
   AND g.expires_at+interval '1 hour'>clock_timestamp()
 ) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='registered upload worker required'; END IF;
 IF report_value->>'completeness'='complete' THEN
  IF prior.scan_id IS NULL THEN
   INSERT INTO public.zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings) VALUES(o,w,e,version_candidate,report_value->>'manifest_digest',report_value->>'origin',credential,report_value->>'ruleset',report_value->'findings') ON CONFLICT(organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset) DO NOTHING;
  END IF;
  -- The version's immutable rule counts must agree on both fresh submissions
  -- and replays of historical receipts. Rule order carries no meaning.
  SELECT id INTO version_value FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset)=(o,w,e,report_value->>'manifest_digest',report_value->>'origin',credential,report_value->>'ruleset')
   AND findings @> (report_value->'findings') AND findings <@ (report_value->'findings');
  IF NOT FOUND OR (prior.scan_id IS NOT NULL AND prior.receipt->>'version_id' IS DISTINCT FROM version_value) THEN
   RETURN '"conflict"'::jsonb;
  END IF;
 END IF;
 IF prior.scan_id IS NOT NULL THEN RETURN prior.receipt; END IF;
 receipt_value:=jsonb_build_object('scan_id',scan_value,'version_id',version_value,'manifest_digest',report_value->'manifest_digest','completeness',report_value->>'completeness','review_path','/inventory/tools?addon='||version_value);
 INSERT INTO public.zasp_addon_scan_receipts(organization_id,workspace_id,environment_id,credential_id,request_key,actor,scan_id,report,receipt) VALUES(o,w,e,credential,key_value,actor_value,scan_value,report_value,receipt_value);
 PERFORM zasp_authorization80.product_settled(proof); RETURN receipt_value;
END $addon_submit$;
