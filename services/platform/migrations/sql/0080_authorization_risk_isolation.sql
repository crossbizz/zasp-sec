-- Source9/10 retained raw API CRUD ACLs on these seven tables. Preserve source
-- callers and ACLs, but force row isolation for direct API reads and deny raw
-- API writes. Existing guarded SECURITY DEFINER projection/mutation functions
-- retain the non-login authority policy, with no new assume-role grant.
CREATE FUNCTION zasp_authorization80.risk_read_allowed(o text,w text,e text,k text,i text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT zasp_authorization80.read_request(o,w,e,CASE k
 WHEN 'finding' THEN ARRAY['getHomeSummary','listFindings','getFinding','globalSearch']
 WHEN 'attack_path' THEN ARRAY['getHomeSummary','listAttackPaths','getAttackPath','getAttackPathBreakOptions']
 ELSE ARRAY[]::text[] END,'view') AND zasp_authorization80.allowed(o,w,e,k,i)
$$;
GRANT EXECUTE ON FUNCTION zasp_authorization80.risk_read_allowed(text,text,text,text,text) TO zasp_discovery_api,zasp_security_agent_api;
DO $risk_isolation$
DECLARE spec text[];owner_name text;
BEGIN
 SELECT principal_name INTO STRICT owner_name FROM public.zasp_discovery_principal_bindings WHERE authority_role='zasp_discovery_authority';
 FOREACH spec SLICE 1 IN ARRAY ARRAY[
 ['zasp_risk_findings','finding','id'],
 ['zasp_risk_finding_evidence','finding','finding_id'],
 ['zasp_risk_finding_factors','finding','finding_id'],
 ['zasp_risk_attack_paths','attack_path','id'],
 ['zasp_risk_attack_path_nodes','attack_path','path_id'],
 ['zasp_risk_attack_path_evidence','attack_path','path_id'],
 ['zasp_risk_break_options','attack_path','path_id']]
 LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=('public.'||spec[1])::regclass AND relowner=owner_name::regrole AND NOT relrowsecurity AND NOT relforcerowsecurity)
  OR EXISTS(SELECT 1 FROM pg_policy WHERE polrelid=('public.'||spec[1])::regclass)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='registered risk isolation predecessor rejected';END IF;
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',spec[1]);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',spec[1]);
  EXECUTE format('CREATE POLICY authorization80_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',spec[1]);
  EXECUTE format('CREATE POLICY authorization80_read ON public.%I FOR SELECT TO zasp_discovery_api,zasp_security_agent_api USING(zasp_authorization80.risk_read_allowed(organization_id,workspace_id,environment_id,%L,%I))',spec[1],spec[2],spec[3]);
 END LOOP;
END $risk_isolation$;
