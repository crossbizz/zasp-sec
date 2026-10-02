-- Artifact authorization follows authoritative stored parents, never an
-- independently granted audit/receipt append identifier. Returned targets carry
-- the operation's original permission (view_audit/view_compliance in Go).
CREATE FUNCTION zasp_authorization80.source_ready(v integer,c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM(VALUES(52,'production_audit_exports','-- authorization80 audit52 checksum','-- authorization80 audit52 fingerprint'),(56,'production_compliance','-- authorization80 compliance56 checksum','-- authorization80 compliance56 fingerprint')) pin(version,name,checksum,fingerprint)
 JOIN public.zasp_schema_versions r ON(r.version,r.name,r.checksum)=(pin.version,pin.name,pin.checksum)
 JOIN public.zasp_schema_metadata m ON(m.key,m.value)=(pin.name||'_fingerprint',pin.fingerprint)
 WHERE(pin.version,pin.checksum,pin.fingerprint)=(v,c,f))
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready() AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready() AND public.zasp_audit_export_workflow_acl_ready()
 AND(v<>56 OR(public.zasp_compliance_worker_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc p JOIN pg_class c ON c.oid='public.zasp_data_controls'::regclass JOIN pg_roles r ON r.oid=c.relowner JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname AND b.authority_role='zasp_discovery_authority' WHERE p.oid=to_regprocedure('public.zasp_compliance_configuration(text,text,text)') AND p.proowner=c.relowner AND r.rolcanlogin))),false)
$$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.source_ready(integer,text,text) TO zasp_discovery_api;
CREATE FUNCTION zasp_authorization80.parent_targets(o text,w text,e text,k text,i text,selector text DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE row_value jsonb;parent_kind text;parent_id text;result jsonb;part jsonb;scope_value record;
BEGIN
 IF i IS NULL THEN
  result:='[]'::jsonb;
  FOR scope_value IN SELECT workspace_id,id FROM public.zasp_environments WHERE organization_id=o AND(k='audit_event' OR(workspace_id,id)=(w,e)) ORDER BY workspace_id,id LOOP
   result:=result||zasp_authorization80.resolve(o,scope_value.workspace_id,scope_value.id,'*',NULL);
   IF jsonb_array_length(result)>10000 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='authorization candidates exceed bound';END IF;
  END LOOP;
  RETURN result;
 END IF;
 IF k='workflow_receipt' THEN
  SELECT to_jsonb(r) INTO row_value FROM public.zasp_workflow_receipts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.receipt_id)=(o,w,e,i);
  parent_kind:=row_value->>'resource_kind';parent_id:=row_value->>'resource_id';
 ELSIF k='security_agent_audit' THEN
  SELECT to_jsonb(r) INTO row_value FROM public.zasp_security_agent_audit r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.audit_id)=(o,w,e,i);
  parent_kind:='security_agent_run';parent_id:=row_value->>'run_id';
 ELSIF k IN('audit_export','compliance_export') THEN
  SELECT v INTO row_value FROM zasp_authorization80.source_rows(o,w,e,k,i) v;
  parent_kind:='environment';parent_id:=row_value->>'environment_id';
 ELSIF k='audit_event' THEN
  SELECT to_jsonb(s) INTO row_value FROM public.zasp_audit_export_public_source_v1 s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.id)=(o,w,e,i) AND(selector IS NULL OR s.source_kind=selector);
  parent_id:=row_value->>'target_id';
  CASE row_value->>'source_kind'
   WHEN 'workflow_policy' THEN parent_kind:='policy';
   WHEN 'red_team_mutation' THEN parent_kind:=CASE WHEN row_value->>'action' IN('test.create','test.update') THEN 'test' WHEN row_value->>'action' IN('test.run.queued','test.run.cancel_requested') THEN 'test_run' END;
   WHEN 'administration' THEN
    CASE row_value->>'action'
     WHEN 'sensor.create','sensor.update','sensor.delete','sensor.token.rotate' THEN
      -- Administration events have an explicit receipt-recorded environment
      -- authority. This policy is stable after sensor deletion; it neither
      -- preserves sensor grants nor falls back from a failed sensor Check.
      IF row_value->>'outcome' IS DISTINCT FROM 'succeeded' OR NOT EXISTS(
       SELECT 1 FROM public.zasp_runtime_sensor_mutations m
       WHERE(m.organization_id,m.workspace_id,m.environment_id,m.principal_id,m.sensor_id,m.created_at)=
        (o,w,e,row_value->>'actor_id',parent_id,(row_value->>'occurred_at')::timestamptz)
       AND m.operation=CASE row_value->>'action' WHEN 'sensor.create' THEN 'createSensorEnrollment' WHEN 'sensor.update' THEN 'updateSensor' WHEN 'sensor.delete' THEN 'deleteSensor' WHEN 'sensor.token.rotate' THEN 'rotateSensorToken' END
       AND i=public.zasp_discovery_canonical_id(o,w,e,'sensor_mutation_audit',jsonb_build_array(m.principal_id,m.operation,m.idempotency_key)::text)
       AND m.result#>>'{body,id}'=parent_id
       AND row_value->'metadata'=jsonb_build_object('sensor_version',m.result#>'{body,version}')
       AND jsonb_typeof(m.result#>'{body,version}')='number'
       AND(m.operation<>'deleteSensor' OR m.result#>>'{body,state}'='deleted')
      ) THEN RETURN '[]'::jsonb;END IF;
      parent_kind:='environment';parent_id:=e;
     WHEN 'data_controls.update' THEN parent_kind:='environment';
     WHEN 'environment.create' THEN parent_kind:='environment';
     WHEN 'environment.update' THEN parent_kind:='environment';
     WHEN 'workspace.update' THEN parent_kind:='workspace';
     WHEN 'workspace.onboard' THEN parent_kind:='workspace';
     WHEN 'session.revoke' THEN parent_kind:='product_session';parent_id:=row_value->'metadata'->>'session_id';
     -- These control-plane events have an explicit recorded environment scope.
     -- This is that scope's view_audit check, never organization member authority.
     WHEN 'api_token.create','api_token.rotate','api_token.revoke','api_token.reveal.acknowledge','group_mapping.update','member.role.update','identity.member.deprovision','identity_provider.createSSOConnection','identity_provider.deleteSSOConnection','identity_provider.testSSOConnection','identity_provider.createSCIMConnection','identity_provider.deleteSCIMConnection' THEN parent_kind:='environment';parent_id:=e;
     ELSE RETURN '[]'::jsonb;
    END CASE;
   ELSE RETURN '[]'::jsonb;
  END CASE;
 ELSIF k='compliance_evidence' THEN
  SELECT to_jsonb(s) INTO row_value FROM public.zasp_compliance_sources(o,w,e) s WHERE(s.source_kind,s.source_id)=(selector,i);
  IF selector IN('administration','workflow_policy','red_team_mutation') THEN RETURN zasp_authorization80.parent_targets(o,w,e,'audit_event',i,selector);END IF;
  parent_id:=i;
  CASE selector
   WHEN 'finding' THEN parent_kind:='finding';
   WHEN 'policy' THEN parent_kind:='policy';
   WHEN 'configuration' THEN parent_kind:='environment';
   WHEN 'red_team_test','attack_lab_test' THEN
    parent_kind:=CASE selector WHEN 'red_team_test' THEN 'test_run' ELSE 'attack_lab_run' END;
    result:=zasp_authorization80.resolve(o,w,e,parent_kind,i);
    part:=zasp_authorization80.resolve(o,w,e,'test',row_value->'metadata'->>'definition_id');
    IF jsonb_array_length(result)=0 OR jsonb_array_length(part)=0 THEN RETURN '[]'::jsonb;END IF;
    RETURN result||part;
   ELSE RETURN '[]'::jsonb;
  END CASE;
 ELSE RETURN '[]'::jsonb;
 END IF;
 IF row_value IS NULL OR parent_kind IS NULL OR parent_id IS NULL THEN RETURN '[]'::jsonb;END IF;
 RETURN zasp_authorization80.resolve(o,w,e,parent_kind,parent_id);
END $$;

CREATE FUNCTION zasp_authorization80.parent_allowed(o text,w text,e text,k text,i text,selector text DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE targets jsonb;target jsonb;
BEGIN
 targets:=zasp_authorization80.parent_targets(o,w,e,k,i,selector);
 IF jsonb_array_length(targets)=0 THEN RETURN false;END IF;
 FOR target IN SELECT value FROM jsonb_array_elements(targets) LOOP
  IF NOT zasp_authorization80.allowed(target->>'organization_id',target->>'workspace_id',target->>'environment_id',target->>'kind',COALESCE(NULLIF(target->>'source_id',''),target->>'id')) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;

-- These are bounded read clones of the exact installed predecessor. Each
-- replacement has an exact expected count; unexpected predecessor definitions
-- stop installation. Historical public definitions and pins remain untouched.
CREATE FUNCTION zasp_authorization80.checked_browser(o text,w text,e text,p text,d bytea,csrf text DEFAULT NULL,fresh boolean DEFAULT false) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $$
DECLARE proof jsonb;
BEGIN
 proof:=zasp_authorization80.context();
 IF csrf IS NOT NULL AND encode(public.digest(csrf,'sha256'),'hex') IS DISTINCT FROM proof->>'csrf_digest' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current browser CSRF binding required';END IF;
 IF proof IS NULL OR(proof->>'organization_id',proof->>'workspace_id',proof->>'environment_id',proof->>'principal_id',proof->>'credential_digest',proof->>'credential_kind') IS DISTINCT FROM(o,w,e,p,encode(d,'hex'),'1') OR(fresh AND NOT COALESCE((proof->>'fresh_auth')::boolean,false)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current browser authorization required';END IF;
 PERFORM zasp_authorization80.identity_fence(proof);
END $$;

DO $read_clones$ DECLARE definition text;old text;replacement text;spec text[];BEGIN
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
 ['public.zasp_audit_export_public_page(text,text,text,text,bytea,text,jsonb,timestamp with time zone,text,integer,text,text)','zasp_audit_export_public_page','audit_page'],
 ['public.zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text)','zasp_compliance_read','compliance_read']]
 LOOP
  definition:=pg_get_functiondef(spec[1]::regprocedure);
  old:='CREATE OR REPLACE FUNCTION public.'||spec[2]||'(';
  IF cardinality(string_to_array(definition,old))<>2 THEN RAISE EXCEPTION 'authorization read clone signature mismatch';END IF;
  definition:=replace(definition,old,'CREATE OR REPLACE FUNCTION zasp_authorization80.'||spec[3]||'(');
  IF spec[3]='audit_page' THEN
   old:='public.zasp_production_audit_exports_readiness(expected_checksum,expected_fingerprint)';
   IF cardinality(string_to_array(definition,old))<>3 THEN RAISE EXCEPTION 'authorization audit readiness clone mismatch';END IF;
   definition:=replace(definition,old,'zasp_authorization80.source_ready(52,expected_checksum,expected_fingerprint)');
   old:='PERFORM public.zasp_audit_export_require_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false);';
   replacement:='PERFORM zasp_authorization80.checked_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,false); PERFORM zasp_authorization80.require_read(org_value,workspace_value,environment_value,ARRAY[''listAuditEvents''],''view_audit'',true,principal_value);';
   -- The pinned public page revalidates its browser both before and after the
   -- bounded capture. Replace both exact occurrences, retaining both gates.
   IF cardinality(string_to_array(definition,old))<>3 THEN RAISE EXCEPTION 'authorization audit identity clone mismatch';END IF;
   definition:=replace(definition,old,replacement);
   old:='WHERE s.organization_id=org_value'||E'\n   AND (NOT filters_value';
   replacement:='WHERE s.organization_id=org_value AND zasp_authorization80.parent_allowed(s.organization_id,s.workspace_id,s.environment_id,''audit_event'',s.id,s.source_kind)'||E'\n   AND (NOT filters_value';
  ELSE
   old:='public.zasp_compliance_readiness(expected_checksum,expected_fingerprint)';
   IF cardinality(string_to_array(definition,old))<>2 THEN RAISE EXCEPTION 'authorization compliance readiness clone mismatch';END IF;
   definition:=replace(definition,old,'zasp_authorization80.source_ready(56,expected_checksum,expected_fingerprint)');
   old:='PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,principal_value,session_value);';
   replacement:='PERFORM zasp_authorization80.checked_browser(org_value,workspace_value,environment_value,principal_value,session_value);';
   replacement:=replacement||E'\n PERFORM zasp_authorization80.require_read(org_value,workspace_value,environment_value,CASE WHEN operation_value IN(''listControls'',''listEvidence'') THEN ARRAY[''listComplianceControls'',''listComplianceEvidence''] WHEN operation_value=''getEvidence'' THEN ARRAY[''getComplianceEvidence''] ELSE ARRAY[]::text[] END,''view_compliance'',true,principal_value); IF operation_value=''getEvidence'' AND ((zasp_authorization80.context()#>>''{path_parameters,sourceKind}'') IS DISTINCT FROM parameters_value->>''source_kind'' OR (zasp_authorization80.context()#>>''{path_parameters,id}'') IS DISTINCT FROM parameters_value->>''source_id'') THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''compliance request binding rejected'';END IF;';
   IF cardinality(string_to_array(definition,old))<>3 THEN RAISE EXCEPTION 'authorization compliance identity clone mismatch';END IF;
   definition:=replace(definition,old,replacement);
   old:='WITH sources AS MATERIALIZED (SELECT * FROM public.zasp_compliance_sources(org_value,workspace_value,environment_value)),';
   replacement:='WITH sources AS MATERIALIZED (SELECT * FROM public.zasp_compliance_sources(org_value,workspace_value,environment_value) s WHERE zasp_authorization80.parent_allowed(org_value,workspace_value,environment_value,''compliance_evidence'',s.source_id,s.source_kind)),';
  END IF;
  IF cardinality(string_to_array(definition,old))<>2 THEN RAISE EXCEPTION 'authorization pre-pagination clone mismatch';END IF;
  EXECUTE replace(definition,old,replacement);
 END LOOP;
END $read_clones$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.audit_page(text,text,text,text,bytea,text,jsonb,timestamptz,text,integer,text,text),zasp_authorization80.compliance_read(text,text,text,text,bytea,text,jsonb,text,text) TO zasp_discovery_api;

CREATE FUNCTION zasp_authorization80.workflow_list(k text,o text,w text,e text,parent_field text,parent_id text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY[CASE k WHEN 'policy' THEN 'listPolicies' WHEN 'integration' THEN 'listIntegrations' WHEN 'security_agent' THEN 'listSecurityAgents' END],'view');
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(body ORDER BY updated_at DESC,id),'[]'::jsonb)) FROM public.zasp_workflow_records
 WHERE(organization_id,workspace_id,environment_id,kind)=(o,w,e,k) AND deleted_at IS NULL AND(parent_field IS NULL OR body->>parent_field=parent_id) AND zasp_authorization80.allowed(o,w,e,k,id));
END
$$;
CREATE FUNCTION zasp_authorization80.workflow_page(k text,o text,w text,e text,a text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY[CASE k WHEN 'policy' THEN 'listPolicies' WHEN 'integration' THEN 'listIntegrations' WHEN 'security_agent' THEN 'listSecurityAgents' END],'view');
 RETURN(WITH candidates AS(SELECT id,body FROM public.zasp_workflow_records WHERE(organization_id,workspace_id,environment_id,kind)=(o,w,e,k) AND deleted_at IS NULL AND(a IS NULL OR id>a) AND zasp_authorization80.allowed(o,w,e,k,id) ORDER BY id LIMIT n+1),visible AS(SELECT * FROM candidates ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',COALESCE((SELECT jsonb_agg(body ORDER BY id) FROM visible),'[]'::jsonb),'next_id',CASE WHEN(SELECT count(*) FROM candidates)>n THEN(SELECT max(id) FROM visible) END));
END
$$;
CREATE FUNCTION zasp_authorization80.receipt_page(o text,w text,e text,p text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM zasp_authorization80.require_read(o,w,e,ARRAY['listWorkflowMutationReceipts'],'view',true,p);
 IF n NOT BETWEEN 1 AND 50 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid workflow receipt list';END IF;
 -- Expired receipt cleanup is not a side effect of a user-authorized read.
 RETURN(SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY created_at DESC,receipt_id),'[]'::jsonb)) FROM(
 SELECT receipt_id,created_at,jsonb_build_object('id',receipt_id,'operation',operation,'idempotency_key',idempotency_key,'intent',intent,'result',result,'resource_kind',resource_kind,'resource_id',resource_id,'resource_version',resource_version,'audit_id',audit_id,'correlation_id',correlation_id,'created_at',created_at,'expires_at',expires_at) item
 FROM public.zasp_workflow_receipts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.principal_id)=(o,w,e,p) AND acknowledged_at IS NULL AND expires_at>transaction_timestamp() AND zasp_authorization80.parent_allowed(o,w,e,'workflow_receipt',receipt_id) ORDER BY created_at DESC,receipt_id LIMIT n) visible);
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.workflow_list(text,text,text,text,text,text),zasp_authorization80.workflow_page(text,text,text,text,text,integer),zasp_authorization80.receipt_page(text,text,text,text,integer) TO zasp_discovery_api,zasp_security_agent_api;

CREATE FUNCTION zasp_authorization80.hierarchy_page(k text,o text,w text,p text,a text,n integer) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb; proof jsonb:=zasp_authorization80.context();
BEGIN
 IF k NOT IN('workspace','environment') OR n NOT BETWEEN 1 AND 101 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='hierarchy page rejected';END IF;
 IF proof IS NULL OR proof->>'organization_id' IS DISTINCT FROM o OR proof->>'principal_id' IS DISTINCT FROM p OR proof->>'collection' IS DISTINCT FROM 'true'
  OR (k='workspace' AND (proof->>'operation_id' IS DISTINCT FROM 'listWorkspaces' OR w IS NOT NULL))
  OR (k='environment' AND (proof->>'operation_id' IS DISTINCT FROM 'listEnvironments' OR proof->>'workspace_selector' IS DISTINCT FROM w))
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='hierarchy request rejected'; END IF;
 IF k='workspace' THEN
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb)) INTO result FROM(
   SELECT x.id,jsonb_build_object('id',x.id,'organization_id',x.organization_id,'name',x.name,'version',x.version) item
   FROM public.zasp_workspaces x WHERE x.organization_id=o AND(a='' OR x.id>a)
   AND EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p,o) s WHERE s.workspace_id=x.id AND zasp_authorization80.allowed(o,s.workspace_id,s.environment_id,'workspace',x.id))
   ORDER BY x.id LIMIT n) visible;
 ELSE
  SELECT jsonb_build_object('items',COALESCE(jsonb_agg(item ORDER BY id),'[]'::jsonb)) INTO result FROM(
   SELECT x.id,jsonb_build_object('id',x.id,'organization_id',x.organization_id,'workspace_id',x.workspace_id,'name',x.name,'environment_class',x.environment_class,'version',x.version) item
   FROM public.zasp_environments x WHERE(x.organization_id,x.workspace_id)=(o,w) AND(a='' OR x.id>a)
   AND EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(p,o) s WHERE(s.workspace_id,s.environment_id)=(x.workspace_id,x.id))
   AND zasp_authorization80.allowed(o,w,x.id,'environment',x.id)
   ORDER BY x.id LIMIT n) visible;
 END IF;
 RETURN result;
END $$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.hierarchy_page(text,text,text,text,text,integer) TO zasp_discovery_api;
