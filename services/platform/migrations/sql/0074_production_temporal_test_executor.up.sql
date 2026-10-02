-- Specialized single-test authority. No73 start is consumed by installation.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal74 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal74 FROM PUBLIC;
CREATE TABLE zasp_temporal74.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal74.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal74.service_grants(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,definition_digest bytea NOT NULL CHECK(octet_length(definition_digest)=32),
 principal_id text NOT NULL,action_key text NOT NULL CHECK(action_key IN('run_test','rerun_test')),
 test_definition_id text NOT NULL,test_definition_version bigint NOT NULL,target_id text NOT NULL,target_kind text NOT NULL,
 grantor_id text NOT NULL,origin text NOT NULL CHECK(origin IN('activation','migration')),
 audit_id text NOT NULL,receipt_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version));
CREATE TABLE zasp_temporal74.grant_revocations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),actor_id text NOT NULL,audit_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES zasp_temporal74.service_grants);
CREATE TABLE zasp_temporal74.backfill_decisions(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 outcome text NOT NULL CHECK(outcome IN('granted','missing_activation_proof','current_permission_denied','current_resource_denied')),evidence jsonb NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version));
CREATE TABLE zasp_temporal74.run_owners(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,source_kind text NOT NULL CHECK(source_kind IN('manual65','automatic73')),
 trigger_id text NOT NULL,trigger_version bigint NOT NULL,input_digest text NOT NULL CHECK(input_digest~'^[a-f0-9]{64}$'),
 action_key text NOT NULL CHECK(action_key IN('run_test','rerun_test')),step_id text NOT NULL,test_run_id text NOT NULL,workflow_id text NOT NULL,
 transferred_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id),UNIQUE(workflow_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','service_grants','grant_revocations','backfill_decisions','run_owners'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal74.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal74.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal74.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN RETURN COALESCE(c='-- test74 checksum' AND f='-- test74 fingerprint' AND zasp_temporal73.ready('-- admission73 checksum','-- admission73 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal74.registration) AND EXISTS(SELECT 1 FROM zasp_temporal74.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal74.fingerprint()=f,false);END $ready$;
CREATE FUNCTION zasp_temporal74.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal74.ready('-- test74 checksum','-- test74 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal74.api_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal74.ready(c,f) AND public.zasp_security_agent_principal_ready('zasp_security_agent_api')
$ready$;
CREATE FUNCTION zasp_temporal74.human(o text,w text,e text,a text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $human$
DECLARE m public.zasp_identity_memberships%ROWTYPE;s public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(a),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test grant scope rejected';END IF;
 SELECT * INTO m FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,a) FOR SHARE;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,a);
 IF m.active IS DISTINCT FROM true OR s.principal_id IS NULL OR NOT COALESCE(s.permissions?&ARRAY['view','manage_workflows','run_tests'] AND public.zasp_effective_scope_permissions(s.permissions,m.role)?&ARRAY['view','manage_workflows','run_tests'],false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test delegation permission rejected';END IF;
END $human$;

CREATE FUNCTION zasp_temporal74.definition(o text,w text,e text,d text,a text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $definition$
DECLARE row_value public.zasp_security_agent_definitions%ROWTYPE;m public.zasp_identity_memberships%ROWTYPE;s public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test definition read unavailable';END IF;
 SELECT * INTO row_value FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR row_value.body->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) THEN RETURN NULL;END IF;
 SELECT * INTO m FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,a) FOR SHARE;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,a);
 IF m.active IS DISTINCT FROM true OR s.principal_id IS NULL OR NOT COALESCE(s.permissions?'view' AND public.zasp_effective_scope_permissions(s.permissions,m.role)?'view',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test definition read denied';END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'definition_id',d,'activation',row_value.activation,'version',row_value.version,'definition_version',row_value.definition_version,'body',row_value.body,'updated_at',to_char(row_value.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $definition$;

-- Preserve the installed domain activation checks, receipts and audit behavior.
-- Only the new explicit current-scope grant writer can call this private copy.
INSERT INTO zasp_temporal74.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid='public.zasp_production_security_agent_existing_tests_activate_core(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)'::regprocedure;
DO $copy$ DECLARE d text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions;
 d:=replace(d,'FUNCTION public.zasp_production_security_agent_existing_tests_activate_core(','FUNCTION zasp_temporal74.activate_core(');
 d:=replace(d,'public.zasp_production_security_agent_run_context_test_binding(','zasp_temporal71.body21(');
 EXECUTE d;
END $copy$;

CREATE FUNCTION zasp_temporal74.activate(o text,w text,e text,d text,a text,k text,v bigint,activation_value text,fresh_value timestamptz,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $activate$
DECLARE row_value public.zasp_security_agent_definitions%ROWTYPE;history public.zasp_security_agent_definition_versions%ROWTYPE;prior public.zasp_security_agent_request_receipts%ROWTYPE;
 binding jsonb;result_value jsonb;intent jsonb;grant_row zasp_temporal74.service_grants%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;grant_audit_value text;grant_body jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='test activation requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test activation unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value)
  AND v BETWEEN 1 AND 999999 AND activation_value IN('validated','supervised','autonomous') AND k~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$'
  AND fresh_value>clock_timestamp() AND fresh_value<=clock_timestamp()+interval '5 minutes 5 seconds',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test activation input rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,a,'activateSecurityAgent',k),0));
 SELECT * INTO row_value FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR UPDATE;
 -- Positive ownership only. Callers retain other action families unchanged.
 IF NOT FOUND OR row_value.body->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) THEN RETURN NULL;END IF;
 PERFORM zasp_temporal74.human(o,w,e,a);
 intent:=jsonb_build_object('activation',activation_value,'expected_version',v,'resource_id',d,'service_delegation',74);
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,a,'activateSecurityAgent',k) FOR SHARE;
 IF FOUND THEN
  -- Existing activation receipts keep the installed domain replay contract.
  -- Replaying one never creates a missing service grant retroactively.
  IF NOT prior.intent?'service_delegation' THEN
   RETURN zasp_temporal74.activate_core(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
  END IF;
  IF prior.intent-'fresh_auth_expires_at' IS DISTINCT FROM intent OR prior.intent_digest IS DISTINCT FROM digest(convert_to(intent::text,'UTF8'),'sha256') OR prior.resource_id<>d OR prior.expected_version<>v OR prior.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='test activation replay conflict';END IF;
  SELECT * INTO grant_row FROM zasp_temporal74.service_grants WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v+1);
  SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,prior.audit_id);
  IF grant_row.receipt_id IS DISTINCT FROM prior.receipt_id OR grant_row.audit_id IS DISTINCT FROM prior.audit_id OR proof.event_kind IS DISTINCT FROM 'test_service_delegated' OR proof.body->'request' IS DISTINCT FROM intent OR proof.body->'response' IS DISTINCT FROM prior.response OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test activation replay evidence unavailable';END IF;
  IF row_value.version<>v+1 OR row_value.activation<>activation_value OR row_value.body->>'autonomy' IS DISTINCT FROM activation_value OR row_value.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR grant_row.definition_digest IS DISTINCT FROM digest(convert_to(row_value.body::text,'UTF8'),'sha256') OR EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v+1)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test activation replay configuration changed';END IF;
  PERFORM zasp_temporal71.body21(o,w,e,d,v+1);
  PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,row_value.body->'allowed_actions'->>0);
  IF NOT COALESCE((prior.intent->>'fresh_auth_expires_at')::timestamptz>clock_timestamp() AND fresh_value>clock_timestamp(),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test delegation authority expired';END IF;
  RETURN prior.response||jsonb_build_object('replayed',true);
 END IF;
 IF row_value.version<>v THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test activation version changed';END IF;
 IF row_value.activation=activation_value AND activation_value IN('supervised','autonomous') THEN
  -- Renewal is a new authorized delegation and configuration revision, never
  -- reinterpretation of an older activation receipt as run_tests permission.
  binding:=zasp_temporal71.body21(o,w,e,d,v);
  PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,row_value.body->'allowed_actions'->>0);
  UPDATE public.zasp_security_agent_definitions SET version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) RETURNING * INTO row_value;
  INSERT INTO public.zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id) VALUES(o,w,e,d,row_value.version,row_value.activation,row_value.body,digest(convert_to(row_value.body::text,'UTF8'),'sha256'),a);
  result_value:=jsonb_build_object('id',d,'activation',activation_value,'enabled',true,'version',row_value.version,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 ELSE
  result_value:=zasp_temporal74.activate_core(o,w,e,d,a,k,v,activation_value,fresh_value,audit_value,correlation_value,receipt_value);
  -- Normal domain activation keeps its original receipt. Its delegation is
  -- recorded separately once its exact final revision has been authenticated.
 END IF;
 IF activation_value IN('supervised','autonomous') THEN
  SELECT * INTO STRICT row_value FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v+1) AND deleted_at IS NULL FOR SHARE;
  SELECT * INTO STRICT history FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v+1) FOR SHARE;
  binding:=zasp_temporal71.body21(o,w,e,d,v+1);
  IF history.definition_digest IS DISTINCT FROM digest(convert_to(row_value.body::text,'UTF8'),'sha256') OR history.definition IS DISTINCT FROM row_value.body OR row_value.body->>'autonomy' IS DISTINCT FROM activation_value OR row_value.body->'enabled' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test grant configuration changed';END IF;
  grant_audit_value:=CASE WHEN EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,a,'activateSecurityAgent',k)) THEN public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_delegation',d||chr(31)||(v+1)::text) ELSE audit_value END;
  INSERT INTO zasp_temporal74.service_grants VALUES(o,w,e,d,v+1,history.definition_digest,public.zasp_discovery_canonical_id(o,w,e,'security_agent_definition_service',d),row_value.body->'allowed_actions'->>0,binding->>'definition_id',(binding->>'definition_version')::bigint,binding->>'target_id',binding->>'target_kind',a,'activation',grant_audit_value,receipt_value,clock_timestamp()) RETURNING * INTO grant_row;
  grant_body:=jsonb_build_object('request',intent,'response',result_value,'grant',to_jsonb(grant_row),'activation_audit_id',audit_value);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,grant_audit_value,correlation_value,a,'test_service_delegated',digest(convert_to(grant_body::text,'UTF8'),'sha256'),grant_body);
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,a,'activateSecurityAgent',k)) THEN
  INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,a,'activateSecurityAgent',k,d,v,intent||jsonb_build_object('fresh_auth_expires_at',fresh_value),digest(convert_to(intent::text,'UTF8'),'sha256'),result_value,audit_value,correlation_value,receipt_value);
 END IF;
 PERFORM zasp_temporal74.human(o,w,e,a);
 IF fresh_value<=clock_timestamp() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test delegation authority expired';END IF;
 RETURN result_value;
END $activate$;

CREATE FUNCTION zasp_temporal74.manager(o text,w text,e text,a text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $manager$
DECLARE m public.zasp_identity_memberships%ROWTYPE;s public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 SELECT * INTO m FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,a) FOR SHARE;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,a);
 IF m.active IS DISTINCT FROM true OR s.principal_id IS NULL OR NOT COALESCE(s.permissions?&ARRAY['view','manage_workflows'] AND public.zasp_effective_scope_permissions(s.permissions,m.role)?&ARRAY['view','manage_workflows'],false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test configuration permission rejected';END IF;
END $manager$;

INSERT INTO zasp_temporal74.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure,
 'public.zasp_security_agent_replay_definition(text,text,text,text,text,text,jsonb)'::regprocedure);
DO $configuration_cores$ DECLARE item record;d text;BEGIN
 FOR item IN SELECT * FROM (VALUES('zasp_security_agent_mutate_definition','configuration_core'),('zasp_security_agent_replay_definition','configuration_replay_core')) x(original,copied) LOOP
  SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature LIKE '%'||item.original||'(%';
  d:=replace(d,'FUNCTION public.'||item.original||'(','FUNCTION zasp_temporal74.'||item.copied||'(');
  d:=replace(d,'public.zasp_production_security_agent_run_context_test_binding(','zasp_temporal71.body21(');
  d:=replace(d,'zasp_production_security_agent_run_context_test_binding(','zasp_temporal71.body21(');
  EXECUTE d;
 END LOOP;
END $configuration_cores$;

CREATE FUNCTION zasp_temporal74.configuration_replay(o text,w text,e text,a text,operation_value text,k text,intent_value jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $replay$
DECLARE current_body jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test configuration unavailable';END IF;
 SELECT body INTO current_body FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,intent_value->>'resource_id');
 IF NOT COALESCE(current_body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) OR current_body IS NULL AND intent_value->'body'->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb),false) THEN RETURN NULL;END IF;
 PERFORM zasp_temporal74.manager(o,w,e,a);
 RETURN zasp_temporal74.configuration_replay_core(o,w,e,a,operation_value,k,intent_value);
END $replay$;

CREATE FUNCTION zasp_temporal74.configuration_write(mutation_value text,d text,o text,w text,e text,a text,operation_value text,k text,v bigint,intent_value jsonb,body_value jsonb,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $write$
DECLARE current_row public.zasp_security_agent_definitions%ROWTYPE;result_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='test configuration requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test configuration unavailable';END IF;
 SELECT * INTO current_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d);
 IF NOT COALESCE(current_row.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) OR current_row.definition_id IS NULL AND body_value->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb),false) THEN RETURN NULL;END IF;
 PERFORM zasp_temporal74.manager(o,w,e,a);
 -- Keep the installed workflow-mirror-before-definition lock order.
 PERFORM 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=(o,w,e,'security_agent',d) FOR UPDATE;
 SELECT * INTO current_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) FOR UPDATE;
 result_value:=zasp_temporal74.configuration_core(mutation_value,d,o,w,e,a,operation_value,k,v,intent_value,body_value,audit_value,correlation_value,receipt_value);
 IF NOT COALESCE((result_value->>'replayed')::boolean,false) AND current_row.definition_id IS NOT NULL THEN
  INSERT INTO zasp_temporal74.grant_revocations(organization_id,workspace_id,environment_id,definition_id,definition_version,actor_id,audit_id)
   SELECT o,w,e,d,g.definition_version,a,audit_value FROM zasp_temporal74.service_grants g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.definition_id,g.definition_version)=(o,w,e,d,current_row.version) ON CONFLICT DO NOTHING;
 END IF;
 PERFORM zasp_temporal74.manager(o,w,e,a);
 RETURN result_value;
END $write$;

-- This is a service authorization predicate, not a run dispatch permit. Actual
-- effect preparation also binds the admitted run/plan/approval/budget journal.
CREATE FUNCTION zasp_temporal74.authorize(o text,w text,e text,d text,v bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorize$
DECLARE configuration public.zasp_security_agent_definitions%ROWTYPE;history public.zasp_security_agent_definition_versions%ROWTYPE;g zasp_temporal74.service_grants%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;binding jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='service authority requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service authority principal rejected';END IF;
 SELECT * INTO configuration FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 SELECT * INTO history FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) FOR SHARE;
 SELECT * INTO g FROM zasp_temporal74.service_grants WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v) FOR SHARE;
 IF g.definition_id IS NULL OR configuration.definition_id IS NULL OR history.definition_id IS NULL OR configuration.activation NOT IN('supervised','autonomous')
  OR configuration.body->>'autonomy' IS DISTINCT FROM configuration.activation OR configuration.body->'enabled' IS DISTINCT FROM 'true'::jsonb
  OR configuration.body->'allowed_actions' IS DISTINCT FROM jsonb_build_array(g.action_key)
  OR g.principal_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_definition_service',d)
  OR history.activation IS DISTINCT FROM configuration.activation OR history.definition IS DISTINCT FROM configuration.body
  OR history.definition_digest IS DISTINCT FROM digest(convert_to(configuration.body::text,'UTF8'),'sha256') OR g.definition_digest IS DISTINCT FROM history.definition_digest
  OR EXISTS(SELECT 1 FROM zasp_temporal74.grant_revocations WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service grant unavailable';END IF;
 SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(o,w,e,g.audit_id) FOR SHARE;
 IF proof.event_kind IS DISTINCT FROM 'test_service_delegated' OR proof.body->'grant' IS DISTINCT FROM to_jsonb(g) OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service grant proof unavailable';END IF;
 binding:=zasp_temporal71.body21(o,w,e,d,v);
 IF (binding->>'definition_id',(binding->>'definition_version')::bigint,binding->>'target_id',binding->>'target_kind') IS DISTINCT FROM(g.test_definition_id,g.test_definition_version,g.target_id,g.target_kind) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service grant target changed';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,g.action_key);
 RETURN jsonb_build_object('principal_id',g.principal_id,'definition_id',d,'definition_version',v,'action_key',g.action_key,'test',binding);
END $authorize$;

CREATE FUNCTION zasp_temporal74.is_owned(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $owned$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
$owned$;
CREATE FUNCTION zasp_temporal74.visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $visible$
 SELECT NOT zasp_temporal74.is_owned(o,w,e,r) OR public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')
$visible$;
CREATE POLICY zasp_temporal74_owner ON public.zasp_security_agent_runs AS RESTRICTIVE USING(current_user='zasp_temporal_accounting' OR zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id)) WITH CHECK(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id));
CREATE POLICY zasp_temporal74_owner ON public.zasp_security_agent_effects AS RESTRICTIVE USING(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id)) WITH CHECK(zasp_temporal74.visible(organization_id,workspace_id,environment_id,run_id));

-- Serialize on the actual parent row before recording the successor. Retained
-- claims take this same lock. Any prior preparation remains with its old owner.
CREATE FUNCTION zasp_temporal74.takeover(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $takeover$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;d public.zasp_security_agent_definitions%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
 t public.zasp_security_agent_trigger_receipts%ROWTYPE;x zasp_temporal74.run_owners%ROWTYPE;source_value text;step_value text;child_value text;binding jsonb;trigger_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='test ownership requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='test ownership principal rejected';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='test ownership scope rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb;END IF;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN RETURN to_jsonb(x);END IF;
 IF rr.state<>'queued' OR rr.version<>1 OR rr.attempt<>0 OR rr.plan_hash IS NOT NULL OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL OR rr.completed_at IS NOT NULL
  OR zasp_temporal66.is_temporal(o,w,e,r)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM zasp_temporal68.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RETURN 'null'::jsonb;END IF;
 SELECT * INTO d FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) AND deleted_at IS NULL FOR SHARE;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) FOR SHARE;
 SELECT * INTO t FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id) FOR SHARE;
 IF d.definition_id IS NULL OR h.definition_id IS NULL OR t.run_id IS NULL OR d.body->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)
  OR d.activation NOT IN('supervised','autonomous') OR d.body->>'autonomy' IS DISTINCT FROM d.activation OR d.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR NOT COALESCE(d.body->'environment_ids'?e,false)
  OR (h.activation,h.definition) IS DISTINCT FROM(d.activation,d.body) OR h.definition_digest IS DISTINCT FROM digest(convert_to(d.body::text,'UTF8'),'sha256') THEN RETURN 'null'::jsonb;END IF;
 IF t.trigger_kind='manual' THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal65.commands c JOIN zasp_temporal66.run_owners old USING(organization_id,workspace_id,environment_id,run_id) WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.kind,c.definition_version,c.input_digest,c.execution_owner,old.execution_owner)=(o,w,e,r,'start',rr.definition_version,encode(t.trigger_digest,'hex'),'legacy','legacy') AND (old.definition_version,old.input_digest)=(c.definition_version,c.input_digest) AND c.accepted_at IS NULL) THEN RETURN 'null'::jsonb;END IF;
  PERFORM public.zasp_sa_manual_provenance(o,w,e,r);
  PERFORM zasp_temporal74.human(o,w,e,rr.requested_by);
  source_value:='manual65';
 ELSE
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions a JOIN zasp_temporal73.commands c USING(organization_id,workspace_id,environment_id,run_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,a.trigger_id,a.trigger_version,a.trigger_digest,a.execution_owner,c.revision,c.kind)=(o,w,e,r,rr.definition_id,rr.definition_version,t.trigger_id,t.trigger_version,t.trigger_digest,'retained_single_action',1,'start')) THEN RETURN 'null'::jsonb;END IF;
  PERFORM zasp_temporal74.authorize(o,w,e,rr.definition_id,rr.definition_version);
  trigger_value:=public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,d.body->>'trigger_source',t.trigger_version);
  IF trigger_value->>'digest' IS DISTINCT FROM encode(t.trigger_digest,'hex') THEN RETURN 'null'::jsonb;END IF;
  source_value:='automatic73';
 END IF;
 binding:=zasp_temporal71.body21(o,w,e,rr.definition_id,rr.definition_version);
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,d.body->'allowed_actions'->>0);
 step_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 child_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_run',r||chr(31)||step_value||chr(31)||(d.body->'allowed_actions'->>0));
 IF EXISTS(SELECT 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child_value)) THEN RETURN 'null'::jsonb;END IF;
 INSERT INTO zasp_temporal74.run_owners(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,source_kind,trigger_id,trigger_version,input_digest,action_key,step_id,test_run_id,workflow_id)
 VALUES(o,w,e,r,rr.definition_id,rr.definition_version,source_value,t.trigger_id,t.trigger_version,encode(t.trigger_digest,'hex'),d.body->'allowed_actions'->>0,step_value,child_value,'security-agent-test/v1/'||o||'/'||w||'/'||e||'/'||r) RETURNING * INTO x;
 RETURN to_jsonb(x);
END $takeover$;

CREATE FUNCTION zasp_temporal74.mutation_guard() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE v jsonb:=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;owned boolean;
BEGIN
 IF TG_TABLE_NAME='zasp_security_agent_runs' AND TG_OP<>'DELETE' AND v->>'state'<>'simulated' AND (TG_OP='INSERT' OR TG_OP='UPDATE' AND OLD.state='queued' AND NEW.state='planning') THEN PERFORM zasp_temporal74.admission_capacity(v);END IF;
 IF TG_TABLE_NAME='zasp_red_team_runs' THEN
  SELECT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,test_run_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'run_id')) INTO owned;
 ELSE owned:=zasp_temporal74.is_owned(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'run_id');END IF;
 IF owned AND (TG_OP='DELETE' OR v->>'lease_owner' IS NOT NULL OR v->>'worker_id' IS NOT NULL OR v->>'lease_token' IS NOT NULL OR v->>'lease_expires_at' IS NOT NULL OR v->>'state'='leased'
  OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation') OR TG_TABLE_NAME='zasp_security_agent_runs' AND public.zasp_security_agent_principal_ready('zasp_security_agent_api'))) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='specialized test rejects retained mutation';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $guard$;
CREATE TRIGGER zasp_temporal74_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal74.mutation_guard();
CREATE TRIGGER zasp_temporal74_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_effects FOR EACH ROW EXECUTE FUNCTION zasp_temporal74.mutation_guard();
CREATE TRIGGER zasp_temporal74_mutation BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_red_team_runs FOR EACH ROW EXECUTE FUNCTION zasp_temporal74.mutation_guard();

-- specialized74 planning
-- specialized74 effects
-- specialized74 invocation
-- specialized74 settlement
-- specialized74 control
-- specialized74 approval
-- specialized74 decisions
-- specialized74 delivery

CREATE FUNCTION zasp_temporal74.serialize_revocation() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $revocation$
BEGIN
 PERFORM 1 FROM zasp_temporal74.service_grants WHERE (organization_id,workspace_id,environment_id,definition_id,definition_version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version) FOR UPDATE;
 RETURN NEW;
END $revocation$;
CREATE TRIGGER serialize_grant BEFORE INSERT ON zasp_temporal74.grant_revocations FOR EACH ROW EXECUTE FUNCTION zasp_temporal74.serialize_revocation();

-- The migration already holds the exclusive schema/configuration/audit locks.
-- Also serialize current membership, scope delegation and activation receipts.
-- No historical login or fresh-auth session is reused as service permission.
LOCK TABLE public.zasp_identity_memberships,public.zasp_authorized_scopes,public.zasp_security_agent_request_receipts IN SHARE ROW EXCLUSIVE MODE;
DO $backfill$
DECLARE d public.zasp_security_agent_definitions%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;p public.zasp_security_agent_audit%ROWTYPE;
 rc public.zasp_security_agent_request_receipts%ROWTYPE;candidate public.zasp_security_agent_request_receipts%ROWTYPE;g zasp_temporal74.service_grants%ROWTYPE;
 binding jsonb;decision text;evidence jsonb;grant_body jsonb;backfill_intent jsonb;proof_count integer;audit_value text;
BEGIN
 FOR d IN SELECT * FROM public.zasp_security_agent_definitions WHERE deleted_at IS NULL AND activation IN('supervised','autonomous') AND body->'enabled'='true'::jsonb AND body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) ORDER BY organization_id,workspace_id,environment_id,definition_id FOR UPDATE LOOP
  decision:='missing_activation_proof';proof_count:=0;evidence:='{}'::jsonb;
  SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version) FOR SHARE;
  backfill_intent:=jsonb_build_object('activation',d.activation,'expected_version',d.version-1,'resource_id',d.definition_id);
  IF h.definition IS NOT DISTINCT FROM d.body AND h.activation IS NOT DISTINCT FROM d.activation AND h.definition_digest=digest(convert_to(d.body::text,'UTF8'),'sha256') AND d.body->>'autonomy'=d.activation THEN
   FOR candidate IN SELECT * FROM public.zasp_security_agent_request_receipts r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.principal_id,r.operation,r.resource_id,r.expected_version)=(d.organization_id,d.workspace_id,d.environment_id,h.actor_id,'activateSecurityAgent',d.definition_id,d.version-1)
    AND r.intent-'fresh_auth_expires_at'=backfill_intent AND r.intent?'fresh_auth_expires_at' AND r.intent_digest=digest(convert_to(backfill_intent::text,'UTF8'),'sha256')
    AND r.response=jsonb_build_object('id',d.definition_id,'activation',d.activation,'enabled',true,'version',d.version,'audit_id',r.audit_id,'correlation_id',r.correlation_id,'receipt_id',r.receipt_id,'replayed',false) FOR SHARE LOOP
    SELECT * INTO p FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id,actor_id,event_kind,correlation_id)=(d.organization_id,d.workspace_id,d.environment_id,candidate.audit_id,h.actor_id,'definition_activated',candidate.correlation_id) FOR SHARE;
    IF p.body=jsonb_build_object('definition_id',d.definition_id,'activation',d.activation,'version',d.version,'allowed_actions',d.body->'allowed_actions') AND p.event_digest=digest(convert_to((p.body-'allowed_actions')::text,'UTF8'),'sha256') THEN
     proof_count:=proof_count+1;rc:=candidate;evidence:=jsonb_build_object('history',to_jsonb(h),'activation_receipt',to_jsonb(candidate),'activation_audit',to_jsonb(p),'migration_version',74);
    END IF;
   END LOOP;
  END IF;
  IF proof_count=1 THEN
   decision:='granted';
   BEGIN PERFORM zasp_temporal74.human(d.organization_id,d.workspace_id,d.environment_id,h.actor_id);
   EXCEPTION WHEN insufficient_privilege THEN decision:='current_permission_denied';END;
   IF decision='granted' THEN
    BEGIN
     binding:=zasp_temporal71.body21(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version);
     PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(d.organization_id,d.workspace_id,d.environment_id,d.body->'allowed_actions'->>0);
    EXCEPTION WHEN insufficient_privilege OR invalid_parameter_value OR serialization_failure OR object_not_in_prerequisite_state THEN decision:='current_resource_denied';END;
   END IF;
   IF decision='granted' THEN
    audit_value:=public.zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'security_agent_test_delegation_migration',d.definition_id||chr(31)||d.version::text);
    INSERT INTO zasp_temporal74.service_grants VALUES(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version,h.definition_digest,public.zasp_discovery_canonical_id(d.organization_id,d.workspace_id,d.environment_id,'security_agent_definition_service',d.definition_id),d.body->'allowed_actions'->>0,binding->>'definition_id',(binding->>'definition_version')::bigint,binding->>'target_id',binding->>'target_kind',h.actor_id,'migration',audit_value,rc.receipt_id,clock_timestamp()) RETURNING * INTO g;
    grant_body:=jsonb_build_object('grant',to_jsonb(g),'origin','migration','evidence',evidence);
    INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body) VALUES(d.organization_id,d.workspace_id,d.environment_id,audit_value,audit_value,g.principal_id,'test_service_delegated',digest(convert_to(grant_body::text,'UTF8'),'sha256'),grant_body);
   END IF;
  END IF;
  INSERT INTO zasp_temporal74.backfill_decisions(organization_id,workspace_id,environment_id,definition_id,definition_version,outcome,evidence) VALUES(d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version,decision,evidence||jsonb_build_object('matching_activation_proofs',proof_count));
 END LOOP;
END $backfill$;

DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal74');
 d:=replace(d,'-- compatibility70 checksum','-- test74 checksum');
 d:=replace(d,'-- compatibility70 fingerprint','-- test74 fingerprint');
 d:=replace(d,'UNION ALL SELECT concat_ws(''|'',''saved''', $tracking$UNION ALL SELECT concat_ws('|','owner-policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polname IN('zasp_temporal74_owner','zasp_temporal74_lock','zasp_temporal74_lock_update','zasp_temporal74_effect_update','zasp_temporal74_effect_delete') AND p.polrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_effects'::regclass)
 UNION ALL SELECT concat_ws('|','lock-role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig) FROM pg_roles WHERE rolname='zasp_temporal74_parent_lock'
 UNION ALL SELECT concat_ws('|','lock-membership',roleid::regrole::text,member::regrole::text,grantor::regrole::text,admin_option,inherit_option,set_option) FROM pg_auth_members WHERE roleid='zasp_temporal74_parent_lock'::regrole OR member='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','lock-schema-grant',n.nspname,a.grantor::regrole::text,a.privilege_type,a.is_grantable) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','lock-table-grant',c.oid::regclass::text,a.grantor::regrole::text,a.privilege_type,a.is_grantable) FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','lock-column-grant',c.attrelid::regclass::text,c.attname,a.grantor::regrole::text,a.privilege_type,a.is_grantable) FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE a.grantee='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','lock-function-grant',p.oid::regprocedure::text,a.grantor::regrole::text,a.privilege_type,a.is_grantable) FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE a.grantee='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','lock-default-grant',d.defaclrole::regrole::text,d.defaclnamespace,d.defaclobjtype,a.grantor::regrole::text,a.privilege_type,a.is_grantable) FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE a.grantee='zasp_temporal74_parent_lock'::regrole
 UNION ALL SELECT concat_ws('|','mutation-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgname='zasp_temporal74_mutation' AND t.tgrelid IN('public.zasp_security_agent_runs'::regclass,'public.zasp_security_agent_effects'::regclass,'public.zasp_red_team_runs'::regclass)
 UNION ALL SELECT concat_ws('|','public-effect-security',c.oid::regclass::text,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.oid='public.zasp_security_agent_effects'::regclass
 UNION ALL SELECT concat_ws('|','public-effect-column-acl',a.attname,COALESCE(a.attacl::text,'')) FROM pg_attribute a WHERE a.attrelid='public.zasp_security_agent_effects'::regclass AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','delivery-role-membership',m.roleid::regrole::text,m.member::regrole::text,m.grantor::regrole::text,m.admin_option,m.inherit_option,m.set_option) FROM pg_auth_members m WHERE m.member IN('zasp_red_team_worker'::regrole,'zasp_red_team_adapter'::regrole)
 UNION ALL SELECT concat_ws('|','approval-dependency',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),p.prosecdef,p.proleakproof,p.proisstrict,p.provolatile,p.proparallel,p.proconfig,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.oid IN('public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)'::regprocedure,'public.zasp_production_security_agent_existing_tests_approval_value(text,text,text,text)'::regprocedure,'public.zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)'::regprocedure)
 UNION ALL SELECT concat_ws('|','approval-read-dependency',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),p.prosecdef,p.proleakproof,p.proisstrict,p.provolatile,p.proparallel,p.proconfig,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.oid IN('public.zasp_production_security_agent_existing_tests_approval_ctx_core(text,text,text,text)'::regprocedure,'public.zasp_production_security_agent_existing_tests_page_ctx_core(text,text,text,text,text,timestamp with time zone,text,integer)'::regprocedure,'public.zasp_production_security_agent_run_context_approval_assemble(text,text,text,text,jsonb,jsonb)'::regprocedure)
 UNION ALL SELECT concat_ws('|','predecessor-compatibility',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),p.prosecdef,p.proleakproof,p.proisstrict,p.provolatile,p.proparallel,p.proconfig,replace(replace(pg_get_functiondef(p.oid),'-- test74 checksum','<checksum>'),'-- test74 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.oid IN('zasp_temporal66.legacy_visible(text,text,text,text)'::regprocedure,'zasp_temporal66.fingerprint()'::regprocedure,'zasp_temporal65.capture()'::regprocedure,'zasp_temporal65.fingerprint()'::regprocedure)
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal74'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
ALTER FUNCTION zasp_temporal74.lock_parent(text,text,text,text,text,text) OWNER TO zasp_temporal74_parent_lock;
ALTER FUNCTION zasp_temporal74.delivery_parent_matches(jsonb) OWNER TO zasp_temporal74_parent_lock;
GRANT EXECUTE ON FUNCTION zasp_temporal74.delivery_parent_matches(jsonb) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_temporal74.delivery_parent_binding(jsonb) TO zasp_temporal74_parent_lock;
GRANT EXECUTE ON FUNCTION zasp_temporal74.lock_parent(text,text,text,text,text,text) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_temporal74.lock_identity(text,text,text,text,text,text) TO zasp_temporal74_parent_lock;
GRANT USAGE ON SCHEMA zasp_temporal74 TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.api_ready(text,text),zasp_temporal74.activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.definition(text,text,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.cancel(text,text,text,text,text,text,bigint,text,text,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.approval(text,text,text,text,text),zasp_temporal74.approval_page(text,text,text,text,text,timestamptz,text,integer,text) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal74.configuration_replay(text,text,text,text,text,text,jsonb),zasp_temporal74.configuration_write(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text) TO zasp_security_agent_api;
GRANT USAGE ON SCHEMA zasp_temporal74 TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.authorize(text,text,text,text,bigint) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal74.takeover(text,text,text,text) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal74.plan(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.effect(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.linked(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal74.test_settle(jsonb) TO zasp_temporal_executor;
GRANT USAGE ON SCHEMA zasp_temporal74 TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal74.adapter_ready(text,text),zasp_temporal74.invocation(jsonb) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_temporal74.adapter_protocol(text,text,text,text,text) TO zasp_red_team_adapter;
GRANT USAGE ON SCHEMA zasp_temporal74 TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal74.visible(text,text,text,text) TO zasp_temporal_accounting;
ALTER FUNCTION zasp_temporal74.capacity(text,text,text,text,text) OWNER TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal74.capacity(text,text,text,text,text) TO zasp_discovery_authority;
GRANT EXECUTE ON FUNCTION zasp_temporal74.unresolved(text,text,text,text) TO zasp_temporal_accounting;
GRANT EXECUTE ON FUNCTION zasp_temporal74.pending(),zasp_temporal74.accept_start(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal74.pending_controls(),zasp_temporal74.accept_control(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal74.inspect(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.test_state(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.cleanup(jsonb) TO zasp_temporal_compensation;
GRANT USAGE ON SCHEMA zasp_temporal74 TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal74.delivery(jsonb),zasp_temporal74.delivery_ready(text,text) TO zasp_red_team_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal74.planning_state(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal74.client_ready(text,text) TO zasp_temporal_executor,zasp_temporal_compensation;
-- specialized74 compatibility
