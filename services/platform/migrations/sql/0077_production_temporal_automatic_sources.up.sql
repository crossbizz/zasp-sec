-- Private in-progress77. CLI registration is withheld until all dependent
-- source/risk/dispatch groups are complete and reviewed. Do not publish alone.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal77 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal77 FROM PUBLIC;
CREATE TABLE zasp_temporal77.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal77.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal77.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal77.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal77.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal77.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
-- automatic77 rules
-- automatic77 runtime
-- automatic77 sources
-- automatic77 matcher
-- automatic77 catchup
-- automatic77 admission
-- automatic77 pages
-- automatic77 outbox
CREATE FUNCTION zasp_temporal77.catalog_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN COALESCE((SELECT count(*)=1 FROM zasp_temporal77.registration) AND EXISTS(SELECT 1 FROM zasp_temporal77.registration WHERE checksum='-- automatic77 checksum' AND fingerprint='-- automatic77 fingerprint') AND zasp_temporal77.fingerprint()='-- automatic77 fingerprint',false);END
$ready$;
CREATE FUNCTION zasp_temporal77.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT c='-- automatic77 checksum' AND f='-- automatic77 fingerprint' AND zasp_temporal77.catalog_ready() AND zasp_temporal76.ready('-- human76 checksum','-- human76 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal77.api_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal77.ready(c,f) AND public.zasp_security_agent_principal_ready('zasp_security_agent_api')
$ready$;
CREATE FUNCTION zasp_temporal77.gateway_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(zasp_temporal77.ready(c,f) AND public.zasp_runtime_principal_ready('zasp_gateway_control'),false)
$ready$;
CREATE FUNCTION zasp_temporal77.executor_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(zasp_temporal77.ready(c,f) AND zasp_temporal68.principal_ready('zasp_temporal_executor'),false)
$ready$;
--75 still owns cadence/revision and the staged single-test definition index.
-- Only77 interprets configured rules; installed-invalid never delegates to75.
CREATE FUNCTION zasp_temporal77.desired(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $desired$
DECLARE result_value jsonb;body_value jsonb;BEGIN
 PERFORM zasp_temporal77.require_executor();
 result_value:=zasp_temporal75.desired(q);
 SELECT body INTO body_value FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id');
 IF body_value ? 'trigger_rules' THEN
  result_value:=result_value||jsonb_build_object('automatic',true,'enabled',(result_value->>'enabled')::boolean AND body_value->'trigger_rules'->>'mode'='automatic' AND zasp_temporal77.rules_valid(body_value) AND zasp_temporal77.rules_capable(body_value));
 END IF;
 RETURN result_value;
END $desired$;
CREATE FUNCTION zasp_temporal77.references(after_value text,limit_value integer) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $refs$
BEGIN PERFORM zasp_temporal77.require_executor();RETURN zasp_temporal75.references(after_value,limit_value);END $refs$;
-- automatic77 policy
-- automatic77 finding
DO $fingerprint$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal77');
 d:=replace(d,'-- compatibility70 checksum','-- automatic77 checksum');
 d:=replace(d,'-- compatibility70 fingerprint','-- automatic77 fingerprint');
 needle:='UNION ALL SELECT concat_ws(''|'',''saved''';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'automatic source fingerprint predecessor changed';END IF;
 d:=replace(d,needle,$tracking$UNION ALL SELECT concat_ws('|','definition-guard',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_definitions'::regclass AND t.tgname='zasp_temporal77_definition_guard'
 UNION ALL SELECT concat_ws('|','source-capture',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE (t.tgrelid,t.tgname) IN(('public.zasp_risk_findings'::regclass,'zasp_temporal77_finding_source'),('public.zasp_risk_attack_paths'::regclass,'zasp_temporal77_path_source'),('public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77_runtime_source'))
 UNION ALL SELECT concat_ws('|','occurrence-guard',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_temporal77_occurrence_guard'
 UNION ALL SELECT concat_ws('|','effective-policy-boundary',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.oid IN('zasp_sa_multistep_prior.deployment_compile(jsonb,boolean)'::regprocedure,'zasp_temporal67.base_fingerprint()'::regprocedure,'zasp_temporal67.fingerprint()'::regprocedure)
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_temporal77'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal77 TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal77.api_ready(text,text) TO zasp_security_agent_api;
GRANT USAGE ON SCHEMA zasp_temporal77 TO zasp_gateway_control;
GRANT EXECUTE ON FUNCTION zasp_temporal77.gateway_ready(text,text) TO zasp_gateway_control;
GRANT USAGE ON SCHEMA zasp_temporal77 TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.executor_ready(text,text),zasp_temporal77.desired(jsonb),zasp_temporal77.references(text,integer) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.scan_sources(integer) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.admit_occurrence(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.dispatch_page(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.catchup_definition(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.pending_sources(integer),zasp_temporal77.attempt_source(text,text,text,text),zasp_temporal77.ack_source(text,text,text,text,text) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal77.record_gateway_event(text,text,bigint,bigint,bytea,bigint,text,text,jsonb,jsonb,timestamp with time zone,jsonb) TO zasp_gateway_control;
GRANT USAGE ON SCHEMA zasp_temporal77 TO zasp_discovery_api;
GRANT EXECUTE ON FUNCTION zasp_temporal77.risk_api_ready(text,text),zasp_temporal77.require_risk_ready(),zasp_temporal77.risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text) TO zasp_discovery_api;
