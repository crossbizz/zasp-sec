-- Explicit private worker profile. No canonical migration or historical pin changes.
CREATE SCHEMA zasp_authorization80_worker AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_authorization80_worker FROM PUBLIC;
CREATE TABLE zasp_authorization80_worker.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_authorization80_worker.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_authorization80_worker.predecessor_views(signature text PRIMARY KEY,definition text NOT NULL);
CREATE TABLE zasp_authorization80_worker.verifiers(purpose text PRIMARY KEY CHECK(purpose IN('worker-forward','captured-compensation')),version text NOT NULL CHECK(version~'^[a-f0-9]{64}$'),key bytea NOT NULL CHECK(octet_length(key)=32));
CREATE TABLE zasp_authorization80_worker.associations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 principal_id text NOT NULL,grantor_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 finding_id text NOT NULL,source_digest text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id));
CREATE TABLE zasp_authorization80_worker.revocations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 revoked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_authorization80_worker.associations);
CREATE TABLE zasp_authorization80_worker.run_state(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_id text NOT NULL,definition_version bigint NOT NULL,state text NOT NULL,run_version bigint NOT NULL,present boolean NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_authorization80_worker.associations);

DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','predecessor_views','verifiers','associations','revocations','run_state'] LOOP
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_authorization80_worker.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_authorization80_worker.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',n);
  IF n NOT IN('verifiers','run_state') THEN EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_worker.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);END IF;
 END LOOP;
END $tables$;

-- Save only identities this stage changes. Full predecessor78 readiness was
-- checked by the installer before these bytes were read.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal78.apply(jsonb)'::regprocedure,'zasp_temporal78.cleanup(jsonb)'::regprocedure,'zasp_temporal78.plan(jsonb)'::regprocedure,'zasp_temporal78.planning_state(jsonb)'::regprocedure,'zasp_temporal78.serialize_revocation()'::regprocedure,'zasp_temporal78.fingerprint()'::regprocedure,'zasp_authorization79.fingerprint()'::regprocedure);
INSERT INTO zasp_authorization80_worker.predecessor_views SELECT oid::regclass::text,pg_get_viewdef(oid) FROM pg_class WHERE oid IN('zasp_authorization79.members'::regclass,'zasp_authorization79.current_grants'::regclass,'zasp_authorization79.resources'::regclass);
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal74.plan(jsonb)'::regprocedure,'zasp_temporal74.planning_state(jsonb)'::regprocedure,'zasp_temporal74.serialize_revocation()'::regprocedure,'zasp_temporal76.executor74_fingerprint()'::regprocedure,'zasp_authorization79.pending(integer)'::regprocedure,'zasp_authorization79.snapshot(text)'::regprocedure,'zasp_authorization80_temporal.projected_domain()'::regprocedure,'zasp_authorization80_temporal.fingerprint()'::regprocedure);

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal74.effect(jsonb)'::regprocedure,'zasp_temporal74.linked(jsonb)'::regprocedure,'zasp_temporal74.test_state(jsonb)'::regprocedure,'zasp_temporal74.invocation(jsonb)'::regprocedure);

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal74.test_validate_output(text,text,text,text,text,jsonb,bytea,jsonb,bytea)'::regprocedure,'zasp_temporal74.test_settle(jsonb)'::regprocedure);

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid='zasp_authorization80_temporal.projected68()'::regprocedure;

-- worker planner portability definitions

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal74.inspect(jsonb)'::regprocedure,'zasp_temporal74.cleanup(jsonb)'::regprocedure);

-- worker runtime bootstrap definitions
CREATE FUNCTION zasp_authorization80_worker.fingerprint() RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $fingerprint$
 WITH facts(v) AS(
 SELECT concat_ws('|','schema',nspowner::regrole::text,nspacl::text) FROM pg_namespace WHERE nspname='zasp_authorization80_worker'
 UNION ALL SELECT concat_ws('|','function',p.oid::regprocedure::text,p.proowner::regrole::text,p.proacl::text,pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_authorization80_worker'::regnamespace OR p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions)
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relowner::regrole::text,c.relacl::text,c.relrowsecurity,c.relforcerowsecurity) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attacl::text,pg_get_expr(d.adbin,d.adrelid)) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON(d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_authorization80_worker'::regnamespace
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl) FROM zasp_authorization80_worker.predecessor_functions
 UNION ALL SELECT concat_ws('|','saved-view',signature,definition) FROM zasp_authorization80_worker.predecessor_views
 UNION ALL SELECT 'runtime-catalog|'||(-- worker inline runtime fingerprint
 )
 UNION ALL SELECT concat_ws('|','runtime-registration',singleton,checksum,fingerprint) FROM zasp_authorization80_runtime.registration
 UNION ALL SELECT concat_ws('|','runtime-stage-insert-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid='public.zasp_runtime_stage_work'::regclass AND t.tgname='zasp_authorization80_runtime_stage_insert'
 UNION ALL SELECT concat_ws('|','runtime-source-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass,'public.zasp_runtime_session_summaries'::regclass,'public.zasp_runtime_gateway_events'::regclass,'zasp_temporal77.runtime_evaluations'::regclass,'zasp_temporal77.source_events'::regclass) AND t.tgname IN('zasp_authorization80_worker_runtime_capture','zasp_authorization80_worker_runtime_no_truncate')
 UNION ALL SELECT concat_ws('|','changed-view',c.oid::regclass::text,c.relowner::regrole::text,c.relacl::text,pg_get_viewdef(c.oid)) FROM pg_class c WHERE c.oid IN(SELECT signature::regclass FROM zasp_authorization80_worker.predecessor_views)
 UNION ALL SELECT concat_ws('|','private-view',c.oid::regclass::text,pg_get_viewdef(c.oid)) FROM pg_class c WHERE c.relnamespace='zasp_authorization80_worker'::regnamespace AND c.relkind='v'
 UNION ALL SELECT concat_ws('|','run-capture-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname IN('zasp_authorization80_worker_run_capture','zasp_authorization80_worker_no_truncate')
 UNION ALL SELECT concat_ws('|','source-capture-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid IN('public.zasp_risk_findings'::regclass,'public.zasp_security_agent_definitions'::regclass) AND t.tgname='zasp_authorization80_worker_source_capture'
 UNION ALL SELECT concat_ws('|','target-capture-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_inventory_source_observations'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass) AND t.tgname IN('zasp_authorization80_worker_target_capture','zasp_authorization80_worker_target_no_truncate')
 UNION ALL SELECT concat_ws('|','discovery-capture-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE (t.tgrelid IN('zasp_temporal72.runs'::regclass,'zasp_temporal72.schedules'::regclass,'public.zasp_integrations'::regclass,'public.zasp_integration_connections'::regclass,'public.zasp_discovery_connection_subjects'::regclass,'public.zasp_connector_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_discovery_source','zasp_authorization80_worker_discovery_no_truncate')) OR (t.tgrelid='public.zasp_workflow_idempotency'::regclass AND t.tgname='zasp_authorization80_worker_discovery_admission')
 UNION ALL SELECT concat_ws('|','ordered-capture-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid='public.zasp_security_agent_runs'::regclass AND t.tgname='zasp_authorization80_worker_ordered_run') OR(t.tgrelid IN('public.zasp_red_team_definitions'::regclass,'public.zasp_inventory_entities'::regclass,'public.zasp_attack_lab_credential_bindings'::regclass,'public.zasp_risk_findings'::regclass,'public.zasp_risk_attack_paths'::regclass,'public.zasp_inventory_evidence'::regclass,'public.zasp_discovery_snapshots'::regclass,'public.zasp_inventory_source_observations'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_target','zasp_authorization80_worker_ordered_no_truncate'))
 UNION ALL SELECT concat_ws('|','ordered-execution-trigger',t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid),pg_get_functiondef(p.oid),p.proowner::regrole::text,p.proacl::text) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE(t.tgrelid IN('public.zasp_gateway_devices'::regclass,'public.zasp_gateway_credentials'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_gateway','zasp_authorization80_worker_ordered_no_truncate')) OR(t.tgrelid IN('public.zasp_workflow_records'::regclass,'public.zasp_security_agent_temporary_policy_targets'::regclass) AND t.tgname IN('zasp_authorization80_worker_ordered_policy','zasp_authorization80_worker_ordered_policy_no_truncate')) OR(t.tgrelid='zasp_temporal68.deliveries'::regclass AND t.tgname IN('ordered_policy_capture','ordered_policy_no_truncate'))
 ) SELECT encode(digest(convert_to(string_agg(v,E'\n' ORDER BY v),'UTF8'),'sha256'),'hex') FROM facts
$fingerprint$;
CREATE FUNCTION zasp_authorization80_worker.catalog_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $catalog$
 SELECT COALESCE((SELECT count(*)=1 FROM zasp_authorization80_worker.registration) AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE fingerprint=(-- worker inline fingerprint
 )),false)
$catalog$;

CREATE FUNCTION zasp_authorization80_worker.operator() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $operator$
 SELECT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
$operator$;
CREATE FUNCTION zasp_authorization80_worker.register_verifier(p text,v text,k bytea) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $register$
DECLARE o text;BEGIN
 IF NOT zasp_authorization80_worker.operator() OR NOT zasp_temporal78.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT COALESCE(p IN('worker-forward','captured-compensation') AND octet_length(k)=32 AND v=encode(digest(k,'sha256'),'hex'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker verifier registration rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('zasp-authorization-worker-key/'||p,0));
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.verifiers WHERE purpose=p AND version=v AND key=k) THEN
  FOR o IN SELECT id FROM public.zasp_organizations ORDER BY id LOOP PERFORM zasp_authorization79.touch(o);END LOOP;
  INSERT INTO zasp_authorization80_worker.verifiers VALUES(p,v,k) ON CONFLICT(purpose) DO UPDATE SET version=EXCLUDED.version,key=EXCLUDED.key;
 END IF;RETURN true;
END $register$;

CREATE FUNCTION zasp_authorization80_worker.key_ready(p text,v text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $key_ready$
 SELECT COALESCE(p IN('worker-forward','captured-compensation') AND zasp_temporal78.current_ready()
 AND zasp_temporal68.principal_ready(CASE p WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END)
 AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.verifiers WHERE purpose=p AND version=v),false)
$key_ready$;

-- A development batch is not a supported runtime profile. This gate remains
-- closed until planning, test, discovery and policy consumers are implemented.
CREATE FUNCTION zasp_authorization80_worker.runtime_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $runtime_ready$
 SELECT zasp_temporal78.current_ready() AND false
$runtime_ready$;

-- worker source definitions

-- worker planning definitions

-- worker test definitions

-- worker test effect definitions

-- worker test adapter definitions

-- worker test completion definitions
-- worker test receipt definitions
-- worker test settlement definitions
-- worker test lifecycle definitions
-- worker discovery source definitions
-- worker discovery fence definitions
-- worker ordered source definitions
-- worker ordered planning definitions

-- This first stage refuses unsigned native calls; the registered proof parser
-- and consuming source checks are deliberately centralized here.
CREATE FUNCTION zasp_authorization80_worker.require_finding(operation_value text,q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $require$
DECLARE envelope json;body_bytes bytea;proof jsonb;source_value jsonb;k bytea;purpose_value text;phase_value text:=operation_value;now_ms bigint:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;revision_value zasp_authorization79.organizations%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker effect requires read committed';END IF;
 purpose_value:=CASE operation_value WHEN 'finding.apply' THEN 'worker-forward' WHEN 'finding.cleanup' THEN 'captured-compensation' ELSE NULL END;
 IF purpose_value IS NULL OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker effect role rejected';END IF;
 -- The native entry selects the receipt-only phase from already committed
 -- evidence. A replay proof can never become fresh apply if that row is absent.
 IF operation_value='finding.apply' AND EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id')) THEN phase_value:='finding.replay';END IF;
 envelope:=NULLIF(current_setting('zasp.worker_proof',true),'')::json;
 IF envelope IS NULL OR octet_length(envelope::text)>65536 OR json_typeof(envelope)<>'object' OR NOT zasp_authorization80.unique_json(envelope) OR (SELECT count(*) FROM json_each(envelope))<>3 OR EXISTS(SELECT 1 FROM json_each(envelope) WHERE key NOT IN('body','version','mac') OR json_typeof(value)<>'string') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';END IF;
 SELECT key INTO k FROM zasp_authorization80_worker.verifiers WHERE purpose=purpose_value AND version=envelope->>'version' FOR SHARE;
 body_bytes:=decode(envelope->>'body','base64');
 IF k IS NULL OR octet_length(body_bytes) NOT BETWEEN 1 AND 32768 OR envelope->>'mac' IS DISTINCT FROM encode(hmac(convert_to('zasp-authorization-'||purpose_value||'-v1','UTF8')||decode('00','hex')||body_bytes,k,'sha256'),'hex') OR NOT zasp_authorization80.unique_json(convert_from(body_bytes,'UTF8')::json) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';END IF;
 proof:=convert_from(body_bytes,'UTF8')::jsonb;
 IF NOT COALESCE(proof->>'purpose'=purpose_value AND proof->>'key_version'=envelope->>'version' AND proof->>'operation'=phase_value AND proof->'request'=q AND proof->>'session_user'=session_user AND (proof->>'issued_at')::bigint<=now_ms+5000 AND (proof->>'expires_at')::bigint>now_ms AND (proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof binding rejected';END IF;
 SELECT * INTO revision_value FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
 IF revision_value.organization_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured organization missing';END IF;
 IF phase_value='finding.apply' THEN
  IF revision_value.desired<>revision_value.applied OR proof->'revision' IS DISTINCT FROM jsonb_build_object('organization_id',revision_value.organization_id,'desired',revision_value.desired,'applied',revision_value.applied,'generation',revision_value.generation,'store_id',revision_value.store_id,'model_id',revision_value.model_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker authorization revision changed';END IF;
 END IF;
 source_value:=zasp_authorization80_worker.finding_source(phase_value,q);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT COALESCE((proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof expired after source locks';END IF;
 IF proof->'facts' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker source changed';END IF;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof rejected';
END $require$;

DO $boundaries$ DECLARE d text;p record;needle text:=E'BEGIN\n';op text;nested text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal78.apply(jsonb)','zasp_temporal78.cleanup(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR (length(p.definition)-length(replace(p.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker native predecessor rejected';END IF;
  op:=CASE p.signature WHEN 'zasp_temporal78.apply(jsonb)' THEN 'finding.apply' ELSE 'finding.cleanup' END;
  d:=p.definition;
  IF op='finding.cleanup' THEN
   nested:=$nested$PERFORM zasp_temporal78.plan((q-ARRAY['reason','input_digest'])||jsonb_build_object('operation','reconcile','payload','{}'::jsonb));$nested$;
   IF(length(d)-length(replace(d,nested,'')))/length(nested)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker captured cleanup predecessor rejected';END IF;
   d:=replace(d,nested,replace(nested,'zasp_temporal78.plan(','zasp_temporal78.recover_plan('));
  END IF;
  EXECUTE replace(d,needle,needle||format(' PERFORM zasp_authorization80_worker.require_finding(%L,q);',op)||E'\n');
 END LOOP;
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal78.plan(jsonb)','zasp_temporal78.planning_state(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR(length(p.definition)-length(replace(p.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker planning predecessor rejected';END IF;
  op:=CASE p.signature WHEN 'zasp_temporal78.plan(jsonb)' THEN 'q->>''operation''' ELSE '''state''' END;
  d:=replace(p.definition,needle,needle||' PERFORM zasp_authorization80_worker.require_planning78('||op||',q);'||E'\n');
  IF p.signature='zasp_temporal78.plan(jsonb)' THEN
   FOREACH op IN ARRAY ARRAY['recover_plan','record_late_usage'] LOOP
    IF(length(d)-length(replace(d,'RETURN zasp_temporal78.'||op||'(q);','')))/length('RETURN zasp_temporal78.'||op||'(q);')<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker recovery predecessor rejected';END IF;
    d:=replace(d,'RETURN zasp_temporal78.'||op||'(q);','RETURN zasp_authorization80_worker.planning78_recovery_result(zasp_temporal78.'||op||'(q));');
   END LOOP;
  END IF;
  EXECUTE d;
 END LOOP;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.serialize_revocation()';
 needle:=' RETURN NEW;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker delegation capture predecessor rejected';END IF;
 EXECUTE replace(d,needle,' PERFORM zasp_authorization80_worker.capture_grant_revocation(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version);'||E'\n'||needle);
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal78.fingerprint()', 'FUNCTION zasp_authorization80_worker.projected78()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker78 fingerprint predecessor rejected';END IF;
 d:=replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_authorization79.fingerprint()';
 d:=replace(d,'FUNCTION zasp_authorization79.fingerprint()', 'FUNCTION zasp_authorization80_worker.projected79()');
 needle:='pg_get_functiondef(p.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker79 fingerprint predecessor rejected';END IF;
 d:=replace(d,needle,$projection$CASE WHEN p.oid IN(SELECT signature::regprocedure FROM zasp_authorization80_worker.predecessor_functions) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
 needle:='pg_get_viewdef(c.oid)';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker79 view predecessor rejected';END IF;
 d:=replace(d,needle,$projection$CASE WHEN c.oid IN(SELECT signature::regclass FROM zasp_authorization80_worker.predecessor_views) THEN(SELECT definition FROM zasp_authorization80_worker.predecessor_views WHERE signature=c.oid::regclass::text) ELSE pg_get_viewdef(c.oid) END$projection$);
 EXECUTE d;
END $boundaries$;
-- worker test catalog definitions
-- worker test activation definitions
-- worker discovery catalog definitions
-- worker ordered catalog definitions
-- worker gateway writer definitions
-- worker runtime module definitions
-- worker runtime catalog definitions
-- worker runtime ancestry definitions
CREATE OR REPLACE FUNCTION zasp_temporal78.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected78() ELSE NULL END
$fingerprint$;
CREATE OR REPLACE FUNCTION zasp_authorization79.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure AND encode(digest(convert_to(p.prosrc,'UTF8'),'sha256'),'hex')='-- worker catalog body digest' AND p.proowner='zasp_discovery_authority'::regrole AND p.prosecdef AND p.provolatile='s' AND l.lanname='sql' AND p.proconfig=ARRAY['search_path=pg_catalog, public'] AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration WHERE checksum='-- worker profile checksum') AND zasp_authorization80_worker.catalog_ready() THEN zasp_authorization80_worker.projected79() ELSE NULL END
$fingerprint$;
DO $owners$ DECLARE p regprocedure;BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_authorization80_worker TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.prepare_finding(jsonb),zasp_authorization80_worker.revision(text) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.finding_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.key_ready(text,text) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_ready() TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning78_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning78_recovery(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.prepare_test74(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning74_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning74_recovery(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_effect_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT USAGE ON SCHEMA zasp_authorization80_worker TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.adapter_revision(text),zasp_authorization80_worker.adapter_key_ready(text,text),zasp_authorization80_worker.adapter74_source(text,jsonb) TO zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_completion_source(text,jsonb),zasp_authorization80_worker.test74_complete(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_receipt_source(text,jsonb),zasp_authorization80_worker.test74_receipt(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_settlement_source(text,jsonb),zasp_authorization80_worker.test74_settle(jsonb) TO zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_lifecycle_source(text,jsonb),zasp_authorization80_worker.test74_recovery_status(jsonb) TO zasp_temporal_compensation;
GRANT USAGE ON SCHEMA zasp_authorization80_worker TO zasp_discovery_worker,zasp_discovery_scheduler;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.discovery72_key_ready(text,text),zasp_authorization80_worker.discovery72_source(text,jsonb),zasp_authorization80_worker.discovery72_execute(jsonb) TO zasp_discovery_worker,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.discovery72_revision(text),zasp_authorization80_worker.prepare_discovery72(jsonb) TO zasp_discovery_worker;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.runtime_ready() TO zasp_discovery_worker,zasp_discovery_scheduler;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.prepare_ordered68(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning68_source(text,jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.planning68_recovery(jsonb) TO zasp_temporal_compensation;
GRANT USAGE ON SCHEMA zasp_authorization80_worker TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.test74_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text) TO zasp_security_agent_api;
