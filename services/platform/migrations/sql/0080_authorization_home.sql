-- Home counts describe authorized rows, not environment-wide health. Only a
-- separate environment Check permits the original complementary health flags.
CREATE FUNCTION zasp_authorization80.home_source_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT COALESCE(zasp_authorization80.ready('-- authorization80 checksum')
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE(version,name,checksum)=(29,'production_home_attention','-- authorization80 home29 checksum'))
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE(key,value)=('production_home_attention_fingerprint','-- authorization80 home29 fingerprint'))
 -- Source14's whole-package guard requires exactly24 inventory functions;
 -- source29 adds retained versioned summary functions. Check the home-specific
 -- live source contracts alongside registered61, without changing old guards.
 AND EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_inventory_cutover_state'::regclass AND relowner='zasp_inventory_authority'::regrole AND relrowsecurity AND relforcerowsecurity AND NOT has_table_privilege('zasp_discovery_api',oid,'SELECT'))
 AND EXISTS(SELECT 1 FROM pg_proc WHERE oid='public.zasp_inventory_scope_state(text,text,text)'::regprocedure AND proowner='zasp_inventory_authority'::regrole AND prosecdef AND COALESCE(proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] AND NOT has_function_privilege('public',oid,'EXECUTE') AND NOT has_function_privilege('zasp_discovery_api',oid,'EXECUTE'))
 AND (SELECT count(*) FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid IN('public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass) AND acl.grantee='zasp_discovery_authority'::regrole AND acl.privilege_type=ANY(ARRAY['SELECT','INSERT','UPDATE','DELETE']) AND NOT acl.is_grantable)=28
 AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid IN('public.zasp_risk_findings'::regclass,'public.zasp_risk_finding_evidence'::regclass,'public.zasp_risk_finding_factors'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_risk_attack_path_nodes'::regclass,'public.zasp_risk_attack_path_evidence'::regclass,'public.zasp_risk_break_options'::regclass) AND acl.grantee='zasp_discovery_authority'::regrole AND (acl.privilege_type<>ALL(ARRAY['SELECT','INSERT','UPDATE','DELETE']) OR acl.is_grantable))
 AND EXISTS(SELECT 1 FROM pg_class c JOIN public.zasp_discovery_principal_bindings b ON b.authority_role='zasp_discovery_authority' AND c.relowner=b.principal_name::regrole WHERE c.oid='public.zasp_risk_attack_paths'::regclass AND c.relrowsecurity AND c.relforcerowsecurity)
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid IN('public.zasp_inventory_entities'::regclass,'public.zasp_security_agent_approvals'::regclass,'public.zasp_security_agent_runs'::regclass)
  AND(relowner<>'zasp_discovery_authority'::regrole OR NOT relrowsecurity OR NOT relforcerowsecurity OR has_table_privilege('zasp_discovery_api',oid,'SELECT')))
 AND NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid IN('public.zasp_inventory_home_summary(text,text,text)'::regprocedure,'public.zasp_inventory_home_summary_v29(text,text,text)'::regprocedure)
  AND(p.proowner<>'zasp_discovery_authority'::regrole OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public'] OR has_function_privilege('public',p.oid,'EXECUTE'))),false)
$$;

DO $home_clone$
DECLARE source text;needle text;replacement text;spec text[];
BEGIN
 source:=pg_get_functiondef('public.zasp_inventory_home_summary_v29(text,text,text)'::regprocedure);
 needle:='FUNCTION public.zasp_inventory_home_summary_v29(';
 IF (length(source)-length(replace(source,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'home source identity mismatch';END IF;
 source:=replace(source,needle,'FUNCTION zasp_authorization80.home_summary(');
 needle:='BEGIN';
 IF (length(source)-length(replace(source,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'home source entry mismatch';END IF;
 source:=replace(source,needle,$entry$BEGIN
 IF NOT COALESCE(zasp_authorization80.home_source_ready() AND public.zasp_discovery_principal_ready('zasp_discovery_api')
 AND (zasp_authorization80.context()->>'organization_id',zasp_authorization80.context()->>'workspace_id',zasp_authorization80.context()->>'environment_id',zasp_authorization80.context()->>'operation_id',zasp_authorization80.context()->>'permission')=(organization_value,workspace_value,environment_value,'getHomeSummary','view'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='current home authorization required';END IF;
 $entry$);
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
  ['entity_value.state,entity_value.product_kind)=(organization_value,workspace_value,environment_value,''active'',''agent'')','agent','entity_value.id'],
  ['path_value.state IN(''observed'',''verified'')','attack_path','path_value.id'],
  ['approval.state=''pending''','security_agent_approval','approval.approval_id'],
  ['run.environment_id=environment_value','security_agent_run','run.run_id']]
 LOOP
  needle:=spec[1];replacement:=needle||format(' AND zasp_authorization80.allowed(organization_value,workspace_value,environment_value,%L,%s)',spec[2],spec[3]);
  IF (length(source)-length(replace(source,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'home source aggregation mismatch';END IF;
  source:=replace(source,needle,replacement);
 END LOOP;
 FOREACH needle IN ARRAY ARRAY[
  'high_risk_value=0 AND pending_approval_value=0 AND needs_human_value=0 AND failed_value=0 AND inconclusive_value=0',
  'high_risk_value>0 OR pending_approval_value>0 OR needs_human_value>0 OR failed_value>0 OR inconclusive_value>0']
 LOOP
  IF (length(source)-length(replace(source,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'home source health mismatch';END IF;
  source:=replace(source,needle,'CASE WHEN COALESCE((zasp_authorization80.context()->>''environment_view'')::boolean,false) THEN ('||needle||') ELSE NULL END');
 END LOOP;
 EXECUTE source;
END $home_clone$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.home_summary(text,text,text) TO zasp_discovery_api;
