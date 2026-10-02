-- Private staged78. Installation/publication stays gated on the complete adapter.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal78 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal78 FROM PUBLIC;
CREATE TABLE zasp_temporal78.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal78.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal78.service_grants(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),principal_id text NOT NULL,grantor_id text NOT NULL,
 action_key text NOT NULL CHECK(action_key='update_finding_response'),audit_id text NOT NULL,receipt_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version));
CREATE TABLE zasp_temporal78.grant_revocations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),actor_id text NOT NULL,audit_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES zasp_temporal78.service_grants);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','service_grants','grant_revocations'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal78.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal78.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal78.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal78.catalog_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN COALESCE((SELECT count(*)=1 FROM zasp_temporal78.registration) AND EXISTS(SELECT 1 FROM zasp_temporal78.registration WHERE checksum='-- finding78 checksum' AND fingerprint='-- finding78 fingerprint') AND zasp_temporal78.fingerprint()='-- finding78 fingerprint',false);END
$ready$;
CREATE FUNCTION zasp_temporal78.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT c='-- finding78 checksum' AND f='-- finding78 fingerprint' AND zasp_temporal78.catalog_ready() AND zasp_temporal77.ready('-- automatic77 checksum','-- automatic77 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal78.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal78.ready('-- finding78 checksum','-- finding78 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal78.api_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal78.ready(c,f) AND public.zasp_security_agent_principal_ready('zasp_security_agent_api')
$ready$;
CREATE FUNCTION zasp_temporal78.client_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal78.ready(c,f) AND (zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation'))
$ready$;
CREATE FUNCTION zasp_temporal78.capable(b jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $capable$
 SELECT COALESCE(b->'allowed_actions'='["update_finding_response"]'::jsonb AND b->>'verification_kind'='finding_state' AND b->>'trigger_kind'='finding' AND b->'max_steps'='1'::jsonb AND NOT b?'existing_test' AND zasp_temporal77.rules_valid(b),false)
$capable$;
CREATE FUNCTION zasp_temporal78.grant_evidence(g zasp_temporal78.service_grants) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public SET timezone TO 'UTC' AS $grant$
 SELECT to_jsonb(g)
$grant$;

-- Copy only domain configuration/read operations, not test binding or execution.
-- The Runner verifies the exact77 ancestry before any private source is copied.
INSERT INTO zasp_temporal78.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'zasp_temporal74.manager(text,text,text,text)'::regprocedure,
 'zasp_temporal74.definition(text,text,text,text,text)'::regprocedure,
 'zasp_temporal74.configuration_replay(text,text,text,text,text,text,jsonb)'::regprocedure,
 'zasp_temporal74.configuration_write(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure,
 'zasp_temporal74.configuration_core(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure,
 'zasp_temporal74.configuration_replay_core(text,text,text,text,text,text,jsonb)'::regprocedure,
 'zasp_temporal77.rules_capable(jsonb)'::regprocedure,'zasp_temporal77.fingerprint()'::regprocedure);
DO $copies$ DECLARE p record;d text;BEGIN
 FOR p IN SELECT * FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal74.%' LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION 'finding configuration predecessor owner changed';END IF;
  d:=replace(p.definition,'zasp_temporal74.','zasp_temporal78.');
  d:=replace(d,'-- test74 checksum','-- finding78 checksum');
  d:=replace(d,'-- test74 fingerprint','-- finding78 fingerprint');
  -- Bound predecessor SQL contains compiled pins, replaced by exact literal.
  d:=replace(d,(SELECT checksum FROM zasp_temporal74.registration),'-- finding78 checksum');
  d:=replace(d,(SELECT fingerprint FROM zasp_temporal74.registration),'-- finding78 fingerprint');
  d:=replace(d,$old$IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)$old$,$new$IN('["update_finding_response"]'::jsonb)$new$);
  d:=replace(d,$old$NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)$old$,$new$NOT IN('["update_finding_response"]'::jsonb)$new$);
  EXECUTE d;
 END LOOP;
END $copies$;

CREATE FUNCTION zasp_temporal78.activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $activate$
DECLARE row_value public.zasp_security_agent_definitions%ROWTYPE;result_value jsonb;g zasp_temporal78.service_grants%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;grant_audit text;grant_body jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='finding activation requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.api_ready('-- finding78 checksum','-- finding78 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding activation unavailable';END IF;
 SELECT * INTO row_value FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR UPDATE;
 IF NOT FOUND OR row_value.body->'allowed_actions' IS DISTINCT FROM '["update_finding_response"]'::jsonb THEN RETURN NULL;END IF;
 PERFORM zasp_temporal78.manager(o,w,e,a);
 IF NOT zasp_temporal78.capable(row_value.body) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding action/source contract rejected';END IF;
 result_value:=zasp_temporal74.activate_core(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
 IF activation_value IN('supervised','autonomous') THEN
  SELECT * INTO STRICT row_value FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v+1) AND deleted_at IS NULL FOR SHARE;
  IF row_value.activation<>activation_value OR row_value.body->'enabled' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding activation changed';END IF;
  grant_audit:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_finding_delegation',d||chr(31)||(v+1)::text);
  IF NOT COALESCE((result_value->>'replayed')::boolean,false) THEN
   INSERT INTO zasp_temporal78.service_grants VALUES(o,w,e,d,v+1,digest(convert_to(row_value.body::text,'UTF8'),'sha256'),public.zasp_discovery_canonical_id(o,w,e,'security_agent_definition_service',d),a,'update_finding_response',grant_audit,receipt_value,clock_timestamp()) RETURNING * INTO g;
   grant_body:=jsonb_build_object('grant',zasp_temporal78.grant_evidence(g),'activation_audit_id',audit_value,'activation_receipt_id',receipt_value,'response',result_value);
   INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,grant_audit,correlation_value,a,'finding_service_delegated',digest(convert_to(grant_body::text,'UTF8'),'sha256'),grant_body);
  ELSE
   SELECT * INTO g FROM zasp_temporal78.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v+1);
   SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(o,w,e,grant_audit);
   IF g.grantor_id IS DISTINCT FROM a OR g.definition_digest IS DISTINCT FROM digest(convert_to(row_value.body::text,'UTF8'),'sha256') OR proof.body->'grant' IS DISTINCT FROM zasp_temporal78.grant_evidence(g) OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256') OR EXISTS(SELECT 1 FROM zasp_temporal78.grant_revocations WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v+1)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding delegation replay unavailable';END IF;
  END IF;
 END IF;
 PERFORM zasp_temporal78.manager(o,w,e,a);
 IF fresh_value<=clock_timestamp() OR NOT zasp_temporal78.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding activation authority expired';END IF;
 RETURN result_value;
END $activate$;

-- finding78 admission

-- finding78 planning

-- finding78 accounting

-- finding78 effect

-- finding78 control

-- finding78 delivery

-- finding78 retained

-- finding78 human

-- finding78 decisions

-- finding78 reads

-- finding78 omitted

-- finding78 approval

-- Narrow effective77 amendments.78 fingerprints every changed live function;
--77 projects only these exact saved definitions and still checks all other bytes.
CREATE OR REPLACE FUNCTION zasp_temporal77.rules_capable(b jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $capability$
 SELECT NOT b ? 'trigger_rules' OR COALESCE(
 b->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND b->>'verification_kind'='test_run'
 AND (b->'trigger_rules'->>'mode'='manual' OR b->>'trigger_kind'='finding' OR b->>'trigger_kind'='attack_path' AND b->>'trigger_source' IN('observed','verified')),false) OR zasp_temporal78.capable(b)
$capability$;
DO $fingerprint$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal78');
 d:=replace(d,(SELECT checksum FROM zasp_temporal70.registration),'-- finding78 checksum');
 d:=replace(d,(SELECT fingerprint FROM zasp_temporal70.registration),'-- finding78 fingerprint');
 needle:='UNION ALL SELECT concat_ws(''|'',''saved''';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding fingerprint predecessor changed';END IF;
 EXECUTE replace(d,needle,$tracking$UNION ALL SELECT concat_ws('|','effective-predecessor',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%' OR signature LIKE 'zasp_temporal73.%' OR signature IN('zasp_temporal74.visible(text,text,text,text)','zasp_temporal76.executor74_fingerprint()','zasp_temporal76.fingerprint()'))
 UNION ALL SELECT concat_ws('|','finding-ownership-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_ownership' AND t.tgrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_effects'::regclass)
 UNION ALL SELECT concat_ws('|','finding-decision-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgname='zasp_temporal78_control_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal77.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal77.fingerprint()', 'FUNCTION zasp_temporal78.predecessor77_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION 'finding77 projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_temporal78.predecessor_functions WHERE signature LIKE 'zasp_temporal77.%') THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
END $fingerprint$;
CREATE OR REPLACE FUNCTION zasp_temporal77.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal78.catalog_ready() THEN zasp_temporal78.predecessor77_fingerprint() ELSE NULL END
$fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_temporal78'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal78 TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal78.run_context(text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal78.approval(text,text,text,text,text),zasp_temporal78.approval_page(text,text,text,text,text,timestamptz,text,integer,text),zasp_temporal78.decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
GRANT USAGE ON SCHEMA zasp_temporal78 TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal78.retained_schedule(text,integer,text,text) TO zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal78.family(text,text,text,text,text),zasp_temporal78.resource(jsonb) TO zasp_security_agent_api;
GRANT USAGE ON SCHEMA zasp_temporal78 TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal78.plan(jsonb),zasp_temporal78.planning_state(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal78.client_ready(text,text) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal78.apply(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal78.inspect(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal78.cleanup(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal78.pending(),zasp_temporal78.accept_start(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal78.pending_controls(),zasp_temporal78.accept_control(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal78.api_ready(text,text),zasp_temporal78.definition(text,text,text,text,text),zasp_temporal78.configuration_replay(text,text,text,text,text,text,jsonb),zasp_temporal78.configuration_write(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text),zasp_temporal78.activate(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text) TO zasp_security_agent_api;
