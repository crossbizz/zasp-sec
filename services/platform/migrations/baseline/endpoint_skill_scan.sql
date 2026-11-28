-- A device reports static counts through its signed inventory. The enrolled
-- device ID identifies the endpoint origin across rotations of its sync token.
ALTER TABLE public.zasp_addon_versions DROP CONSTRAINT zasp_addon_versions_origin_check;
ALTER TABLE public.zasp_addon_versions ADD CONSTRAINT zasp_addon_versions_origin_check
 CHECK(origin IN ('ci','local','private_worker','endpoint'));

CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_skill_versions(o text,w text,e text,device text,items jsonb)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,public AS $scan$
DECLARE item jsonb; scan jsonb; counts jsonb; report jsonb; digest text; skipped integer;
BEGIN
 IF EXISTS (SELECT FROM jsonb_array_elements(items) i GROUP BY i->>'installation_id' HAVING count(*)>1) THEN
  RAISE invalid_parameter_value;
 END IF;
 FOR item IN SELECT i FROM jsonb_array_elements(items) i WHERE i?'skill_scan' LOOP
  scan:=item->'skill_scan';
  IF jsonb_typeof(scan) IS DISTINCT FROM 'object' OR NOT scan ?& ARRAY['ruleset','rule_counts','skipped_count']
    OR scan-ARRAY['ruleset','rule_counts','skipped_count'] <> '{}'::jsonb OR scan->>'ruleset' IS DISTINCT FROM 'zasp-static.v2'
    OR jsonb_typeof(scan->'rule_counts') IS DISTINCT FROM 'object'
    OR jsonb_typeof(scan->'skipped_count') IS DISTINCT FROM 'number' OR (scan->>'skipped_count') !~ '^(0|[1-9][0-9]{0,3})$'
  THEN RAISE invalid_parameter_value; END IF;
  skipped:=(scan->>'skipped_count')::integer;
  IF skipped>1024 OR (item?'manifest_digest') IS DISTINCT FROM (skipped=0) THEN RAISE invalid_parameter_value; END IF;
  IF EXISTS(SELECT FROM jsonb_each(scan->'rule_counts') f WHERE jsonb_typeof(f.value)<>'number'
    OR (f.value::text) !~ '^[1-9][0-9]{0,3}$') THEN RAISE invalid_parameter_value; END IF;
  IF EXISTS(SELECT FROM jsonb_each_text(scan->'rule_counts') f WHERE f.value::integer>1024) THEN RAISE invalid_parameter_value; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('rule_id',key,'count',value) ORDER BY key COLLATE "C"),'[]'::jsonb)
    INTO counts FROM jsonb_each(scan->'rule_counts');
  digest:=item->>'manifest_digest';
  -- Reuse the registry's closed, versioned findings catalog without granting
  -- the device permission to submit a local, CI or private-worker scan.
  report:=jsonb_build_object('schema_version','zasp-addon-findings.v1','environment_id',e,'manifest_method','addon-manifest.v1',
    'ruleset',scan->>'ruleset','manifest_digest',digest,'completeness',CASE WHEN skipped=0 THEN 'complete' ELSE 'partial' END,
    'origin','local','findings',counts,'skipped_count',skipped);
  IF NOT zasp_authorization80.addon_report_valid(report,e) THEN RAISE invalid_parameter_value; END IF;
  IF skipped=0 THEN
   INSERT INTO public.zasp_addon_versions(organization_id,workspace_id,environment_id,id,manifest_digest,origin,origin_credential,ruleset,findings)
    VALUES(o,w,e,'pid_'||gen_random_uuid(),digest,'endpoint',device,scan->>'ruleset',counts)
    ON CONFLICT(organization_id,workspace_id,environment_id,manifest_digest,origin,origin_credential,ruleset) DO NOTHING;
   IF NOT EXISTS(SELECT FROM public.zasp_addon_versions v WHERE
      (v.organization_id,v.workspace_id,v.environment_id,v.manifest_digest,v.origin,v.origin_credential,v.ruleset)
       =(o,w,e,digest,'endpoint',device,scan->>'ruleset') AND v.findings=counts) THEN
    -- Roll back every new version in this batch before reporting the conflict.
    RAISE EXCEPTION USING ERRCODE='ZSC01', MESSAGE='inconsistent endpoint scan';
   END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN SQLSTATE 'ZSC01' THEN RETURN false;
END $scan$;
ALTER FUNCTION zasp_authorization80.endpoint_skill_versions(text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.endpoint_skill_versions(text,text,text,text,jsonb) FROM PUBLIC;

-- The read projection adds the review ID without changing the signed snapshot
-- that is compared when a device retries a generation.
CREATE OR REPLACE FUNCTION zasp_authorization80.endpoint_skill_detail(o text,w text,e text,device text,item jsonb)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $detail$
 SELECT item || coalesce((SELECT jsonb_build_object('skill_version_id',v.id) FROM public.zasp_addon_versions v
 WHERE item?'skill_scan' AND (v.organization_id,v.workspace_id,v.environment_id,v.manifest_digest,v.origin,v.origin_credential,v.ruleset)
   =(o,w,e,item->>'manifest_digest','endpoint',device,item#>>'{skill_scan,ruleset}')),'{}'::jsonb)
$detail$;
ALTER FUNCTION zasp_authorization80.endpoint_skill_detail(text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.endpoint_skill_detail(text,text,text,text,jsonb) FROM PUBLIC;

DO $install_endpoint_scan$
DECLARE source text; anchor text;
BEGIN
 SELECT pg_get_functiondef('zasp_authorization80.endpoint_machine(text,text,text,text,text,text,bigint,text,jsonb)'::regprocedure) INTO source;
 IF position('endpoint_skill_versions' IN source)=0 THEN
  anchor:='x-ARRAY[''installation_id'',''manifest_digest'']';
  IF position(anchor IN source)=0 THEN RAISE EXCEPTION 'endpoint installation validation unavailable'; END IF;
  source:=replace(source,anchor,'x-ARRAY[''installation_id'',''manifest_digest'',''skill_scan'']');
  anchor:='octet_length(q::text)>65536';
  IF position(anchor IN source)=0 THEN RAISE EXCEPTION 'endpoint envelope bound unavailable'; END IF;
  source:=replace(source,anchor,'octet_length(q::text)>(CASE WHEN op=''recordEndpointInventory'' THEN 98304 ELSE 65536 END)');
  anchor:='  INSERT INTO public.zasp_endpoint_partitions(';
  IF position(anchor IN source)=0 THEN RAISE EXCEPTION 'endpoint snapshot insertion unavailable'; END IF;
  source:=replace(source,anchor,$body$
  IF NOT zasp_authorization80.endpoint_skill_versions(o,w,e,target_id,v->'installations') THEN RETURN '"conflict"'::jsonb; END IF;
$body$||anchor);
  EXECUTE source;
 END IF;
 SELECT pg_get_functiondef('zasp_authorization80.endpoint_admin(text,text,text,text,text,text,text,bigint,jsonb)'::regprocedure) INTO source;
 IF position('endpoint_skill_detail' IN source)=0 THEN
  anchor:='jsonb_agg(inst ORDER BY inst->>''installation_id'')';
  IF position(anchor IN source)=0 THEN RAISE EXCEPTION 'endpoint installation detail unavailable'; END IF;
  EXECUTE replace(source,anchor,'jsonb_agg(zasp_authorization80.endpoint_skill_detail(o,w,e,target_id,inst) ORDER BY inst->>''installation_id'')');
 END IF;
END $install_endpoint_scan$;
