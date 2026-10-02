-- The predecessor's source and compiled pins remain immutable. Save only the
-- enumerated functions changed by this release, with exact rollback definitions.
DO $guard$
BEGIN
 IF NOT public.zasp_production_security_agent_existing_tests_readiness('-- predecessor compliance checksum','-- predecessor compliance fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance predecessor unavailable';
 END IF;
END $guard$;
CREATE SCHEMA zasp_compliance_predecessor AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_compliance_predecessor FROM PUBLIC;
DO $compatibility$
DECLARE signature_value text; definition_value text; name_value text; needle text; occurrences integer; check_value text:=current_setting('check_function_bodies');
BEGIN
 FOREACH signature_value IN ARRAY ARRAY[
 'zasp_production_security_agent_existing_tests_readiness(text,text)',
 'zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
 'zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
 'zasp_production_security_agent_attack_path_security_ready()',
 'zasp_production_workflow_compatibility_security_ready()'] LOOP
  name_value:=split_part(signature_value,'(',1);
  definition_value:=pg_get_functiondef(('public.'||signature_value)::regprocedure);
  EXECUTE replace(definition_value,'FUNCTION public.'||name_value||'(','FUNCTION zasp_compliance_predecessor.'||name_value||'(');
  EXECUTE format('ALTER FUNCTION zasp_compliance_predecessor.%s OWNER TO zasp_discovery_authority',signature_value);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_compliance_predecessor.%s FROM PUBLIC',signature_value);
  IF name_value='zasp_production_security_agent_existing_tests_readiness' THEN
   IF strpos(definition_value,'count(*)=55')=0 OR strpos(definition_value,'version>55')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance exact predecessor rejected';END IF;
   definition_value:=replace(replace(definition_value,'count(*)=55','count(*)=56'),'version>55','version>56');
   needle:='public.zasp_production_security_agent_existing_tests_live_fingerprint()=expected_fingerprint';
   IF (length(definition_value)-length(replace(definition_value,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance predecessor fingerprint rejected';END IF;
   definition_value:=replace(definition_value,needle,'public.zasp_compliance_readiness((SELECT value FROM public.zasp_schema_metadata WHERE key=''production_compliance_checksum''),(SELECT value FROM public.zasp_schema_metadata WHERE key=''production_compliance_fingerprint''))');
  ELSE
   occurrences:=0;
   FOREACH needle IN ARRAY ARRAY['later_release."version" > 55','later."version">55','later."version" > 55'] LOOP
    occurrences:=occurrences+(length(definition_value)-length(replace(definition_value,needle,'')))/length(needle);
    definition_value:=replace(definition_value,needle,replace(needle,'55','56'));
   END LOOP;
   IF occurrences<>(CASE WHEN name_value IN('zasp_workflow_mutate','zasp_risk_mutate') THEN 1 ELSE 3 END) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance compatibility predecessor rejected';END IF;
  END IF;
  PERFORM set_config('check_function_bodies','off',true);
  EXECUTE definition_value;
 END LOOP;
 PERFORM set_config('check_function_bodies',check_value,true);
END $compatibility$;

-- Fingerprint ancestry excludes exactly the two new root metadata entries.
DO $ancestry$
DECLARE definition_value text; needle text;
BEGIN
 definition_value:=pg_get_functiondef('zasp_existing_tests_predecessor.audit_fingerprint()'::regprocedure);
 needle:='''production_security_agent_existing_tests_checksum'',''production_security_agent_existing_tests_fingerprint''';
 IF (length(definition_value)-length(replace(definition_value,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance fingerprint ancestry rejected';END IF;
 definition_value:=replace(definition_value,needle,needle||',''production_compliance_checksum'',''production_compliance_fingerprint''');
 EXECUTE replace(definition_value,'FUNCTION zasp_existing_tests_predecessor.audit_fingerprint(','FUNCTION zasp_compliance_predecessor.audit_fingerprint(');
 definition_value:=pg_get_functiondef('zasp_existing_tests_predecessor.budget_fingerprint()'::regprocedure);
 EXECUTE replace(replace(definition_value,'FUNCTION zasp_existing_tests_predecessor.budget_fingerprint(','FUNCTION zasp_compliance_predecessor.budget_fingerprint('),'zasp_existing_tests_predecessor.audit_fingerprint()','zasp_compliance_predecessor.audit_fingerprint()');
 definition_value:=pg_get_functiondef('zasp_existing_tests_predecessor.run_context_fingerprint()'::regprocedure);
 EXECUTE replace(replace(definition_value,'FUNCTION zasp_existing_tests_predecessor.run_context_fingerprint(','FUNCTION zasp_compliance_predecessor.run_context_fingerprint('),'zasp_existing_tests_predecessor.budget_fingerprint()','zasp_compliance_predecessor.budget_fingerprint()');
 definition_value:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_live_fingerprint()'::regprocedure);
 EXECUTE replace(replace(definition_value,'FUNCTION public.zasp_production_security_agent_existing_tests_live_fingerprint(','FUNCTION zasp_compliance_predecessor.existing_tests_fingerprint('),'zasp_existing_tests_predecessor.run_context_fingerprint()','zasp_compliance_predecessor.run_context_fingerprint()');
 ALTER FUNCTION zasp_compliance_predecessor.audit_fingerprint() OWNER TO zasp_discovery_authority;
 ALTER FUNCTION zasp_compliance_predecessor.budget_fingerprint() OWNER TO zasp_discovery_authority;
 ALTER FUNCTION zasp_compliance_predecessor.run_context_fingerprint() OWNER TO zasp_discovery_authority;
 ALTER FUNCTION zasp_compliance_predecessor.existing_tests_fingerprint() OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_compliance_predecessor.audit_fingerprint(),zasp_compliance_predecessor.budget_fingerprint(),zasp_compliance_predecessor.run_context_fingerprint(),zasp_compliance_predecessor.existing_tests_fingerprint() FROM PUBLIC;
END $ancestry$;

-- compliance jobs fragment

CREATE FUNCTION public.zasp_compliance_function_identity(function_value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT CASE WHEN function_value=to_regprocedure('public.zasp_compliance_readiness(text,text)')
 THEN regexp_replace(pg_get_functiondef(function_value),$$expected_(checksum|fingerprint) = '[a-f0-9]{64}'$$,$$expected_\1 = '<compiled-pin>'$$,'g')
 ELSE pg_get_functiondef(function_value) END
$identity$;
CREATE FUNCTION public.zasp_compliance_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_compliance_predecessor.existing_tests_fingerprint())
 UNION ALL SELECT concat_ws('|','jobs',public.zasp_compliance_jobs_catalog())
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_compliance_predecessor'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),CASE WHEN p.oid=to_regprocedure('public.zasp_compliance_configuration(text,text,text)') THEN public.zasp_audit_export_source_catalog_role(p.proowner,(SELECT relowner FROM pg_class WHERE oid='public.zasp_data_controls'::regclass)) ELSE r.rolname END,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),CASE WHEN p.oid=to_regprocedure('public.zasp_compliance_configuration(text,text,text)') THEN public.zasp_audit_export_source_catalog_acl(p.proacl,(SELECT relowner FROM pg_class WHERE oid='public.zasp_data_controls'::regclass))::text ELSE COALESCE(p.proacl::text,'') END,public.zasp_compliance_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='zasp_compliance_predecessor' OR n.nspname='public' AND starts_with(p.proname,'zasp_compliance_')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_compliance_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $readiness$
 SELECT COALESCE(expected_checksum = '-- compiled compliance checksum'
 AND expected_fingerprint = '-- compiled compliance fingerprint'
 AND (SELECT count(*)=56 FROM public.zasp_schema_versions)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>56)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_budgets_predecessor_releases() p LEFT JOIN public.zasp_schema_versions r USING(version) WHERE r.name IS DISTINCT FROM p.name OR r.checksum IS DISTINCT FROM p.checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=53 AND name='production_security_agent_budgets' AND checksum='-- compliance budget checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=54 AND name='production_security_agent_run_context' AND checksum='-- compliance context checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=55 AND name='production_security_agent_existing_tests' AND checksum='-- predecessor compliance checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_checksum' AND value='-- compliance budget checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_budgets_fingerprint' AND value='-- compliance budget fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_checksum' AND value='-- compliance context checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_run_context_fingerprint' AND value='-- compliance context fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_checksum' AND value='-- predecessor compliance checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_existing_tests_fingerprint' AND value='-- predecessor compliance fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=56 AND name='production_compliance' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_compliance_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_compliance_fingerprint' AND value=expected_fingerprint)
 AND public.zasp_production_runtime_sandbox_binding_security_ready()
 AND public.zasp_audit_export_policy_state_ready() AND public.zasp_audit_export_worker_security_ready()
 AND public.zasp_audit_export_source_acl_ready() AND public.zasp_audit_export_workflow_acl_ready()
 AND public.zasp_compliance_worker_security_ready()
 AND EXISTS(SELECT 1 FROM pg_proc p JOIN pg_class c ON c.oid='public.zasp_data_controls'::regclass JOIN pg_roles r ON r.oid=c.relowner JOIN public.zasp_discovery_principal_bindings b ON b.principal_name=r.rolname AND b.authority_role='zasp_discovery_authority' WHERE p.oid=to_regprocedure('public.zasp_compliance_configuration(text,text,text)') AND p.proowner=c.relowner AND r.rolcanlogin)
 AND public.zasp_compliance_live_fingerprint()=expected_fingerprint,false)
$readiness$;

CREATE FUNCTION public.zasp_compliance_api_ready(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $api$
 SELECT public.zasp_compliance_readiness(expected_checksum,expected_fingerprint) AND public.zasp_discovery_principal_ready('zasp_discovery_api')
$api$;

CREATE FUNCTION public.zasp_compliance_authorize(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authorize$
DECLARE session_row public.zasp_product_sessions%ROWTYPE; member_row public.zasp_identity_memberships%ROWTYPE;
BEGIN
 SELECT * INTO session_row FROM public.zasp_product_sessions WHERE token_digest=session_value AND (organization_id,workspace_id,environment_id,principal_id)=(org_value,workspace_value,environment_value,principal_value) FOR SHARE;
 IF NOT FOUND OR session_row.revoked_at IS NOT NULL OR session_row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance session rejected';END IF;
 SELECT * INTO member_row FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(org_value,principal_value) FOR SHARE;
 IF NOT FOUND OR NOT member_row.active THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance membership rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(principal_value,org_value) s WHERE (s.organization_id,s.workspace_id,s.environment_id)=(org_value,workspace_value,environment_value) AND s.permissions ?& ARRAY['view_compliance','view','view_audit']) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance source permission rejected';END IF;
 IF session_row.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='compliance session expired';END IF;
END $authorize$;

-- Product mappings describe evidence categories, not regulatory completeness.
-- The 24-hour age is a product freshness policy, not a legal interval.
CREATE FUNCTION public.zasp_compliance_mappings() RETURNS TABLE(framework text,control_id text,label text,required_sources text[],maximum_age_seconds integer) LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $mapping$
 SELECT f.framework,f.framework||'-'||c.category,c.label,c.sources,86400
 FROM (VALUES('soc2_security'),('hipaa')) f(framework)
 CROSS JOIN (VALUES('audit','Audit review',ARRAY['audit']),('findings','Finding review',ARRAY['finding']),('policies','Policy definitions',ARRAY['policy']),('tests','Completed security tests',ARRAY['test']),('configuration','Collection and retention configuration',ARRAY['configuration'])) c(category,label,sources)
$mapping$;

CREATE FUNCTION public.zasp_compliance_valid_target(kind_value text,id_value text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $target$
 SELECT COALESCE(CASE
 WHEN kind_value='policy' THEN id_value ~ '^policy-[a-z0-9][a-z0-9-]{0,120}$'
 WHEN kind_value IN('administration','workflow_policy','red_team_mutation') THEN id_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
 WHEN kind_value IN('finding','red_team_test','attack_lab_test','configuration') THEN public.zasp_valid_product_id(id_value)
 ELSE false END,false)
$target$;

-- Fixed source branches; no caller-controlled relation names or scope fields.
-- Attempts retain their run-recorded definition version after definition edits.
-- Keep the inherited configuration table ACL unchanged. This helper remains
-- owned by its verified registered migration owner; only the authority calls it.
CREATE FUNCTION public.zasp_compliance_configuration(org_value text,workspace_value text,environment_value text)
RETURNS TABLE(environment_id text,version bigint,updated_at timestamptz,migration_seeded boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $configuration$
 SELECT d.environment_id,d.version,d.updated_at,d.migration_seeded FROM public.zasp_data_controls d
 WHERE (d.organization_id,d.workspace_id,d.environment_id)=(org_value,workspace_value,environment_value)
$configuration$;
REVOKE ALL ON FUNCTION public.zasp_compliance_configuration(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_configuration(text,text,text) TO zasp_discovery_authority;
CREATE FUNCTION public.zasp_compliance_sources(org_value text,workspace_value text,environment_value text)
RETURNS TABLE(source_kind text,source_id text,source_version bigint,source_family text,source_time timestamptz,metadata jsonb,source_valid boolean)
LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $sources$
 SELECT a.source_kind,a.id,1::bigint,'audit',a.occurred_at,jsonb_build_object('action',a.action,'status',a.outcome),a.source_valid
 FROM public.zasp_audit_export_public_source_v1 a WHERE (a.organization_id,a.workspace_id,a.environment_id)=(org_value,workspace_value,environment_value)
 UNION ALL
 SELECT 'finding',f.id,f.version,'finding',f.updated_at,jsonb_build_object('status',f.status,'severity',f.severity,'evidence_ids',COALESCE((SELECT jsonb_agg(e.evidence_id ORDER BY e.position) FROM public.zasp_risk_finding_evidence e WHERE (e.organization_id,e.workspace_id,e.environment_id,e.finding_id)=(org_value,workspace_value,environment_value,f.id)),'[]'::jsonb)),true
 FROM public.zasp_risk_findings f WHERE (f.organization_id,f.workspace_id,f.environment_id)=(org_value,workspace_value,environment_value)
 UNION ALL
 SELECT 'policy',p.id,p.version,'policy',p.updated_at,jsonb_build_object('verification','definition_only'),public.zasp_compliance_valid_target('policy',p.id)
 FROM public.zasp_workflow_records p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.kind)=(org_value,workspace_value,environment_value,'policy') AND p.deleted_at IS NULL
 UNION ALL
 SELECT 'red_team_test',r.run_id,r.attempt::bigint,'test',r.completed_at,jsonb_build_object('status',r.verdict,'definition_id',r.definition_id,'definition_version',r.definition_version,'receipt_sha256',encode(a.evidence_checksum,'hex'),'receipt_version',a.evidence_version_id,'receipt_size',a.evidence_size),
 COALESCE(a.completed_at=r.completed_at AND a.input_digest=r.input_digest AND a.verdict=r.verdict AND a.evidence_checksum=r.evidence_checksum AND a.evidence_version_id=r.evidence_version_id AND a.evidence_reference=r.evidence_reference AND a.evidence_key=r.evidence_key AND a.evidence_size=r.evidence_size AND octet_length(a.evidence_checksum)=32 AND a.evidence_checksum<>decode(repeat('00',32),'hex') AND a.evidence_version_id<>'' AND a.evidence_size>0,false)
 FROM public.zasp_red_team_runs r LEFT JOIN public.zasp_red_team_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.attempt)
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.state)=(org_value,workspace_value,environment_value,'complete')
 UNION ALL
 SELECT 'attack_lab_test',r.run_id,r.attempt::bigint,'test',r.completed_at,jsonb_build_object('status',r.verdict,'definition_id',r.definition_id,'definition_version',r.definition_version,'receipt_sha256',encode(a.evidence_checksum,'hex'),'receipt_version',a.evidence_version_id,'receipt_size',a.evidence_size),
 COALESCE(a.evidence_state='complete' AND a.completed_at=r.completed_at AND a.input_digest=r.input_digest AND a.verdict=r.verdict AND a.evidence_checksum=r.evidence_checksum AND a.evidence_version_id=r.evidence_version_id AND a.evidence_reference=r.evidence_reference AND a.evidence_key=r.evidence_key AND a.evidence_size=r.evidence_size AND octet_length(a.evidence_checksum)=32 AND a.evidence_checksum<>decode(repeat('00',32),'hex') AND a.evidence_version_id<>'' AND a.evidence_size>0,false)
 FROM public.zasp_attack_lab_runs r LEFT JOIN public.zasp_attack_lab_attempts a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.attempt)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.attempt)
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.state)=(org_value,workspace_value,environment_value,'complete')
 UNION ALL
 SELECT 'configuration',d.environment_id,d.version,'configuration',d.updated_at,jsonb_build_object('migration_seeded',d.migration_seeded,'verification',CASE WHEN d.migration_seeded THEN 'unverified' ELSE 'configured' END),true
 FROM public.zasp_compliance_configuration(org_value,workspace_value,environment_value) d
$sources$;

CREATE FUNCTION public.zasp_compliance_read(org_value text,workspace_value text,environment_value text,principal_value text,session_value bytea,operation_value text,parameters_value jsonb,expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE result_value jsonb;items_value jsonb;cursor_value jsonb;last_value jsonb;limit_value integer:=100;framework_value text;control_value text;family_value text;kind_value text;id_value text;version_value bigint;stamp timestamptz:=statement_timestamp();next_value jsonb;
BEGIN
 IF NOT public.zasp_compliance_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance release unavailable';END IF;
 IF NOT public.zasp_discovery_principal_ready('zasp_discovery_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='compliance API authority rejected';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[org_value,workspace_value,environment_value,principal_value]) v WHERE NOT public.zasp_valid_product_id(v)) OR octet_length(session_value) IS DISTINCT FROM 32 OR session_value=decode(repeat('00',32),'hex') OR parameters_value IS NULL OR jsonb_typeof(parameters_value)<>'object' OR octet_length(parameters_value::text)>4096 OR operation_value IS NULL OR operation_value NOT IN('listControls','listEvidence','getEvidence') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance request rejected';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(parameters_value) k WHERE k<>ALL(CASE WHEN operation_value='getEvidence' THEN ARRAY['source_kind','source_id','source_version'] ELSE ARRAY['framework','control_id','limit','cursor'] END)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance parameter rejected';END IF;
 PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,principal_value,session_value);
 framework_value:=parameters_value->>'framework';control_value:=parameters_value->>'control_id';
 IF parameters_value ? 'framework' AND (jsonb_typeof(parameters_value->'framework')<>'string' OR framework_value NOT IN('soc2_security','hipaa')) OR parameters_value ? 'control_id' AND (jsonb_typeof(parameters_value->'control_id')<>'string' OR NOT EXISTS(SELECT 1 FROM public.zasp_compliance_mappings() m WHERE m.control_id=control_value AND (framework_value IS NULL OR m.framework=framework_value))) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance filter rejected';END IF;
 SELECT required_sources[1] INTO family_value FROM public.zasp_compliance_mappings() m WHERE m.control_id=control_value;
 IF parameters_value ? 'limit' THEN
  IF jsonb_typeof(parameters_value->'limit')<>'number' OR parameters_value->>'limit' !~ '^[1-9][0-9]{0,2}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance page size rejected';END IF;
  limit_value:=(parameters_value->>'limit')::integer;
  IF limit_value>100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance page size rejected';END IF;
 END IF;
 cursor_value:=parameters_value->'cursor';
 IF parameters_value ? 'cursor' THEN
  IF jsonb_typeof(cursor_value)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(cursor_value))<>8 OR cursor_value->>'organization_id' IS DISTINCT FROM org_value OR cursor_value->>'workspace_id' IS DISTINCT FROM workspace_value OR cursor_value->>'environment_id' IS DISTINCT FROM environment_value OR cursor_value->>'operation' IS DISTINCT FROM operation_value OR cursor_value->>'framework' IS DISTINCT FROM COALESCE(framework_value,'') OR cursor_value->>'control_id' IS DISTINCT FROM COALESCE(control_value,'') OR jsonb_typeof(cursor_value->'source_kind')<>'string' OR jsonb_typeof(cursor_value->'source_id')<>'string' OR EXISTS(SELECT 1 FROM jsonb_object_keys(cursor_value) k WHERE k<>ALL(ARRAY['organization_id','workspace_id','environment_id','operation','framework','control_id','source_kind','source_id'])) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance cursor rejected';END IF;
  IF operation_value='listEvidence' AND NOT public.zasp_compliance_valid_target(cursor_value->>'source_kind',cursor_value->>'source_id') OR operation_value='listControls' AND NOT EXISTS(SELECT 1 FROM public.zasp_compliance_mappings() m WHERE m.framework=cursor_value->>'source_kind' AND m.control_id=cursor_value->>'source_id') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance cursor rejected';END IF;
 END IF;
 IF operation_value='getEvidence' THEN
  kind_value:=parameters_value->>'source_kind';id_value:=parameters_value->>'source_id';
  IF NOT public.zasp_compliance_valid_target(kind_value,id_value) OR jsonb_typeof(parameters_value->'source_kind') IS DISTINCT FROM 'string' OR jsonb_typeof(parameters_value->'source_id') IS DISTINCT FROM 'string' OR parameters_value ? 'source_version' AND (jsonb_typeof(parameters_value->'source_version')<>'number' OR parameters_value->>'source_version' !~ '^[1-9][0-9]{0,14}$') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='compliance target rejected';END IF;
  version_value:=(parameters_value->>'source_version')::bigint;
 END IF;
 -- Materialize every eligible row once in this statement. Invalid sources must
 -- fail collection even when a first page or a category filter excludes them.
 WITH sources AS MATERIALIZED (SELECT * FROM public.zasp_compliance_sources(org_value,workspace_value,environment_value)),
 checked AS (SELECT COALESCE(bool_and(source_valid AND source_time IS NOT NULL AND source_time<=stamp AND source_version>0 AND public.zasp_compliance_valid_target(source_kind,source_id)),true) valid FROM sources),
 page AS (SELECT * FROM sources s WHERE operation_value<>'listControls' AND (family_value IS NULL OR s.source_family=family_value) AND (operation_value<>'getEvidence' OR (s.source_kind,s.source_id)=(kind_value,id_value)) AND (cursor_value IS NULL OR (s.source_kind COLLATE "C",s.source_id COLLATE "C")>(cursor_value->>'source_kind' COLLATE "C",cursor_value->>'source_id' COLLATE "C")) ORDER BY s.source_kind COLLATE "C",s.source_id COLLATE "C" LIMIT limit_value+1),
 controls AS (SELECT m.*,CASE WHEN NOT EXISTS(SELECT 1 FROM sources s WHERE s.source_family=ANY(m.required_sources) AND COALESCE((s.metadata->>'migration_seeded')::boolean,false)=false) THEN 'missing' WHEN NOT EXISTS(SELECT 1 FROM sources s WHERE s.source_family=ANY(m.required_sources) AND s.source_time>=stamp-m.maximum_age_seconds*interval '1 second' AND COALESCE((s.metadata->>'migration_seeded')::boolean,false)=false) THEN 'stale' ELSE 'fresh' END freshness,to_char(COALESCE((SELECT max(s.source_time)+m.maximum_age_seconds*interval '1 second' FROM sources s WHERE s.source_family=ANY(m.required_sources) AND COALESCE((s.metadata->>'migration_seeded')::boolean,false)=false),'1970-01-01 00:00:00+00'::timestamptz) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') fresh_until FROM public.zasp_compliance_mappings() m WHERE operation_value='listControls' AND (framework_value IS NULL OR m.framework=framework_value) AND (control_value IS NULL OR m.control_id=control_value) AND (cursor_value IS NULL OR (m.framework COLLATE "C",m.control_id COLLATE "C")>(cursor_value->>'source_kind' COLLATE "C",cursor_value->>'source_id' COLLATE "C")) ORDER BY m.framework COLLATE "C",m.control_id COLLATE "C" LIMIT limit_value+1)
 SELECT jsonb_build_object('valid',(SELECT valid FROM checked),'items',CASE WHEN operation_value='listControls' THEN COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.framework COLLATE "C",c.control_id COLLATE "C") FROM controls c),'[]'::jsonb) ELSE COALESCE((SELECT jsonb_agg(jsonb_build_object('id',s.source_id,'asset',s.source_id,'source',s.source_family,'timestamp',to_char(s.source_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'organization_id',org_value,'workspace_id',workspace_value,'environment_id',environment_value,'target',jsonb_build_object('source_kind',s.source_kind,'source_id',s.source_id,'source_version',s.source_version),'freshness',CASE WHEN s.source_time<stamp-interval '24 hours' THEN 'stale' ELSE 'fresh' END,'metadata',s.metadata) ORDER BY s.source_kind COLLATE "C",s.source_id COLLATE "C") FROM page s),'[]'::jsonb) END) INTO result_value;
 IF NOT (result_value->>'valid')::boolean THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance invalid source';END IF;
 items_value:=result_value->'items';
 IF operation_value='getEvidence' THEN
  IF jsonb_array_length(items_value)=0 THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='compliance source not found';END IF;
  IF jsonb_array_length(items_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='compliance source identity collision';END IF;
  IF version_value IS NOT NULL AND (items_value->0->'target'->>'source_version')::bigint<>version_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='compliance source_changed';END IF;
  result_value:=items_value->0;
 ELSE
  IF jsonb_array_length(items_value)>limit_value THEN
   items_value:=items_value-limit_value;last_value:=items_value->(limit_value-1);
   next_value:=jsonb_build_object('organization_id',org_value,'workspace_id',workspace_value,'environment_id',environment_value,'operation',operation_value,'framework',COALESCE(framework_value,''),'control_id',COALESCE(control_value,''),'source_kind',CASE WHEN operation_value='listControls' THEN last_value->>'framework' ELSE last_value->'target'->>'source_kind' END,'source_id',CASE WHEN operation_value='listControls' THEN last_value->>'control_id' ELSE last_value->'target'->>'source_id' END);
  END IF;
  result_value:=jsonb_build_object('mapping_revision','product-evidence-v1','collected_at',to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'items',items_value,'next_cursor',next_value);
 END IF;
 PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,principal_value,session_value);
 RETURN result_value;
END $read$;

DO $acl$
DECLARE signature_value text;
BEGIN
 FOR signature_value IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND starts_with(p.proname,'zasp_compliance_') AND p.proname<>'zasp_compliance_configuration' LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',signature_value);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature_value);
 END LOOP;
END $acl$;
GRANT EXECUTE ON FUNCTION public.zasp_compliance_api_ready(text,text),public.zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text) TO zasp_discovery_api;
