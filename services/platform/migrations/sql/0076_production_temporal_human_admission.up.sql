-- Human single-test requests retain65 receipts and original human identities.
-- This additive release owns new admissions from commit, before74 delivery.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal76 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal76 FROM PUBLIC;
CREATE TABLE zasp_temporal76.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal76.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal76.predecessor_constraints(signature text PRIMARY KEY,definition text NOT NULL);
CREATE TABLE zasp_temporal76.admissions(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 event_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 requester_id text NOT NULL,source_kind text NOT NULL CHECK(source_kind IN('manual65','resource65')),
 trigger_id text NOT NULL,trigger_version bigint NOT NULL,input_digest text NOT NULL CHECK(input_digest~'^[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,event_id) REFERENCES zasp_temporal65.commands(organization_id,workspace_id,environment_id,event_id));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','predecessor_constraints','admissions'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal76.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal76.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal76.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal76.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal76.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal76.catalog_ready() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN COALESCE((SELECT count(*)=1 FROM zasp_temporal76.registration) AND EXISTS(SELECT 1 FROM zasp_temporal76.registration WHERE checksum='-- human76 checksum' AND fingerprint='-- human76 fingerprint') AND zasp_temporal76.fingerprint()='-- human76 fingerprint',false);END
$ready$;
CREATE FUNCTION zasp_temporal76.ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT c='-- human76 checksum' AND f='-- human76 fingerprint' AND zasp_temporal76.catalog_ready() AND zasp_temporal75.ready('-- selector75 checksum','-- selector75 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal76.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal76.ready('-- human76 checksum','-- human76 fingerprint')
$ready$;
CREATE FUNCTION zasp_temporal76.api_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal76.ready(c,f) AND public.zasp_security_agent_principal_ready('zasp_security_agent_api')
$ready$;

-- A positive family result checks the actual scoped definition and current
-- human permission. Absence is not evidence that legacy handling is safe.
CREATE FUNCTION zasp_temporal76.family(o text,w text,e text,d text,actor text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $family$
DECLARE b jsonb;s public.zasp_authorized_scopes%ROWTYPE;BEGIN
 IF NOT zasp_temporal76.current_ready() OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='human test admission unavailable';END IF;
 s:=zasp_sa_multistep_prior.lock_scope(o,w,e,actor);
 IF s.principal_id IS NULL OR NOT COALESCE(s.permissions?'view',false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='human scope denied';END IF;
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='human test scope denied';END IF;
 IF b->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) AND b->'max_steps'='1'::jsonb THEN PERFORM zasp_temporal74.human(o,w,e,actor);RETURN true;END IF;
 RETURN false;
END $family$;

-- Copy the accepted human request and product admission bodies. No service
-- grant and no automatic73 receipt is minted for a human request.
INSERT INTO zasp_temporal76.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('public.zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text)'::regprocedure,'zasp_temporal70.body02(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure);
DO $copies$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal76.predecessor_functions WHERE signature='zasp_temporal70.body02(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 d:=replace(d,'FUNCTION zasp_temporal70.body02(','FUNCTION zasp_temporal76.admit_body(');
 needle:=$count$(SELECT count(*) FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND state IN('queued','planning','waiting_approval','running','verifying','contained'))$count$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'human admission count predecessor changed';END IF;
 d:=replace(d,needle,'zasp_temporal73.active_count(o,w,e,d)');
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal76.predecessor_functions WHERE signature='zasp_production_security_agent_existing_tests_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text,text,text)';
 d:=replace(d,'FUNCTION public.zasp_production_security_agent_existing_tests_run(','FUNCTION zasp_temporal76.run_body(');
 d:=replace(d,'expected_fingerprint text)','expected_fingerprint text, human_contract jsonb)');
 needle:=$intent$intent_value:=jsonb_build_object('definition_id',d,'expected_version',v,'trigger_kind',k,'trigger_id',t);$intent$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'human intent predecessor changed';END IF;
 d:=replace(d,needle,replace(needle,');',')||human_contract;'));
 d:=replace(d,'public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint)','zasp_temporal76.current_ready()');
 d:=replace(d,'public.zasp_production_security_agent_run_context_test_binding(','zasp_temporal71.body21(');
 d:=replace(d,'public.zasp_production_security_agent_existing_tests_admit(','zasp_temporal76.admit_body(');
 d:=replace(d,'kind_value:=CASE k',$human$PERFORM zasp_temporal74.human(o,w,e,actor_value);
 kind_value:=CASE k$human$);
 needle:=' result_value:=(public.zasp_production_security_agent_existing_tests_admit(';
 -- The call name above was replaced already. Bind new request intent before
 -- validating its live source, without changing the original replay branch.
 needle:=replace(needle,'public.zasp_production_security_agent_existing_tests_admit','zasp_temporal76.admit_body');
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'human first admission predecessor changed';END IF;
 d:=replace(d,needle,$source$ IF human_contract ? 'trigger_version' THEN
  IF NOT COALESCE(jsonb_typeof(human_contract->'trigger_version')='number' AND human_contract->>'trigger_version'~'^[1-9][0-9]{0,6}$' AND human_contract->>'trigger_source'=definition_body->>'trigger_source',false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='human source contract changed';END IF;
  PERFORM public.zasp_production_security_agent_existing_tests_trigger(o,w,e,kind_value,t,human_contract->>'trigger_source',(human_contract->>'trigger_version')::bigint);
 END IF;
$source$||needle);
 EXECUTE d;
END $copies$;

CREATE FUNCTION zasp_temporal76.resource(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $resource$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';d text:=q->>'definition_id';a text:=q->>'actor_id';b jsonb;source_value jsonb;result_value jsonb;k text;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='human admission requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','definition_id','actor_id','idempotency_key','definition_version','run_id','trigger_kind','trigger_id','audit_id','correlation_id','receipt_id']||CASE WHEN q ? 'trigger_version' OR q ? 'trigger_source' THEN ARRAY['trigger_version','trigger_source'] ELSE ARRAY[]::text[] END) OR octet_length(q::text)>8192 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='human admission request rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 IF NOT zasp_temporal76.family(o,w,e,d,a) THEN RETURN 'null'::jsonb;END IF;
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,(q->>'definition_version')::bigint) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='human definition changed';END IF;
 source_value:=CASE WHEN q ? 'trigger_version' THEN jsonb_build_object('trigger_version',q->'trigger_version','trigger_source',q->'trigger_source') ELSE '{}'::jsonb END;
 result_value:=zasp_temporal76.run_body(o,w,e,d,a,q->>'idempotency_key',(q->>'definition_version')::bigint,q->>'run_id',q->>'trigger_kind',q->>'trigger_id',q->>'audit_id',q->>'correlation_id',q->>'receipt_id','','',source_value);
 PERFORM zasp_temporal74.human(o,w,e,a);
 RETURN result_value;
END $resource$;

CREATE FUNCTION zasp_temporal76.capture() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;t public.zasp_security_agent_trigger_receipts%ROWTYPE;c zasp_temporal65.commands%ROWTYPE;b jsonb;BEGIN
 IF NEW.operation<>'runSecurityAgent' THEN RETURN NEW;END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.response->>'id');
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.definition_id,rr.definition_version);
 IF b->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) OR b->'max_steps'<>'1'::jsonb THEN RETURN NEW;END IF;
 SELECT * INTO c FROM zasp_temporal65.commands WHERE(organization_id,workspace_id,environment_id,run_id,kind)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,'start');
 -- A new request for an old occurrence must never transfer historical work.
 IF c.event_id IS DISTINCT FROM NEW.receipt_id OR NEW.response->'replayed'='true'::jsonb THEN RETURN NEW;END IF;
 IF NOT zasp_temporal76.current_ready() OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR c.execution_owner<>'legacy' OR rr.state<>'queued' OR rr.version<>1 OR rr.attempt<>0 OR rr.requested_by<>NEW.principal_id THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='human ownership capture rejected';END IF;
 PERFORM zasp_temporal74.human(rr.organization_id,rr.workspace_id,rr.environment_id,rr.requested_by);
 SELECT * INTO STRICT t FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id);
 INSERT INTO zasp_temporal76.admissions VALUES(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,c.event_id,rr.definition_id,rr.definition_version,rr.requested_by,CASE WHEN t.trigger_kind='manual' THEN 'manual65' ELSE 'resource65' END,t.trigger_id,t.trigger_version,c.input_digest);
 RETURN NEW;
END $capture$;
CREATE TRIGGER zasp_temporal76_capture AFTER INSERT ON public.zasp_security_agent_request_receipts FOR EACH ROW EXECUTE FUNCTION zasp_temporal76.capture();

DO $visibility$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal75.visible(text,text,text,text)'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal75.','zasp_temporal76.');EXECUTE d;
END $visibility$;
CREATE POLICY zasp_temporal76_owner ON public.zasp_security_agent_runs AS RESTRICTIVE
 USING(CASE WHEN current_user IN('zasp_temporal_accounting','zasp_temporal74_parent_lock') THEN true ELSE zasp_temporal76.visible(organization_id,workspace_id,environment_id,run_id) END)
 WITH CHECK(zasp_temporal76.visible(organization_id,workspace_id,environment_id,run_id));

-- Exact installed changes: four74 functions and one source discriminator.
-- Their prior definitions remain frozen;76 fingerprints the effective bodies.
INSERT INTO zasp_temporal76.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.fingerprint()'::regprocedure);
INSERT INTO zasp_temporal76.predecessor_constraints SELECT conrelid::regclass::text||'.'||conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='zasp_temporal74.run_owners'::regclass AND conname='run_owners_source_kind_check';
ALTER TABLE zasp_temporal74.run_owners DROP CONSTRAINT run_owners_source_kind_check;
ALTER TABLE zasp_temporal74.run_owners ADD CONSTRAINT run_owners_source_kind_check CHECK(source_kind IN('manual65','automatic73','resource65'));
DO $executor$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal76.predecessor_functions WHERE signature='zasp_temporal74.takeover(text,text,text,text)';
 needle:=$old$ ELSE
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions$old$;
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'human takeover predecessor changed';END IF;
 d:=replace(d,needle,$new$ ELSIF EXISTS(SELECT 1 FROM zasp_temporal76.admissions m JOIN zasp_temporal65.commands c ON(c.organization_id,c.workspace_id,c.environment_id,c.event_id)=(m.organization_id,m.workspace_id,m.environment_id,m.event_id)
  WHERE(m.organization_id,m.workspace_id,m.environment_id,m.run_id,m.definition_id,m.definition_version,m.requester_id,m.source_kind,m.trigger_id,m.trigger_version,m.input_digest,c.kind,c.execution_owner)=(o,w,e,r,rr.definition_id,rr.definition_version,rr.requested_by,'resource65',t.trigger_id,t.trigger_version,encode(t.trigger_digest,'hex'),'start','legacy') AND c.accepted_at IS NULL) THEN
  PERFORM zasp_temporal74.human(o,w,e,rr.requested_by);
  trigger_value:=public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,d.body->>'trigger_source',t.trigger_version);
  IF t.trigger_kind IS DISTINCT FROM d.body->>'trigger_kind' OR trigger_value->>'digest' IS DISTINCT FROM encode(t.trigger_digest,'hex') THEN RETURN 'null'::jsonb;END IF;
  source_value:='resource65';
 ELSE
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal73.admissions$new$);
 EXECUTE d;
 SELECT definition INTO STRICT d FROM zasp_temporal76.predecessor_functions WHERE signature='zasp_temporal74.context(text,text,text,text)';
 needle:=$old$ ELSE
  PERFORM zasp_temporal74.authorize(o,w,e,rr.definition_id,rr.definition_version);$old$;
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION 'human context predecessor changed';END IF;
 d:=replace(d,needle,$new$ ELSIF x.source_kind='resource65' THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_temporal76.admissions m JOIN zasp_temporal65.commands c ON(c.organization_id,c.workspace_id,c.environment_id,c.event_id)=(m.organization_id,m.workspace_id,m.environment_id,m.event_id)
   WHERE(m.organization_id,m.workspace_id,m.environment_id,m.run_id,m.requester_id,m.definition_id,m.definition_version,m.trigger_id,m.trigger_version,m.input_digest,m.source_kind,c.kind)=(o,w,e,r,rr.requested_by,rr.definition_id,rr.definition_version,x.trigger_id,x.trigger_version,x.input_digest,'resource65','start')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='human resource provenance changed';END IF;
  PERFORM zasp_temporal74.human(o,w,e,rr.requested_by);
  source_value:=public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,d.body->>'trigger_source',t.trigger_version);
  IF t.trigger_kind IS DISTINCT FROM d.body->>'trigger_kind' OR source_value->>'digest' IS DISTINCT FROM x.input_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='human resource source changed';END IF;
 ELSE
  PERFORM zasp_temporal74.authorize(o,w,e,rr.definition_id,rr.definition_version);$new$);
 EXECUTE d;
 -- Native invocation uses the locked parent-value variant, copied at74
 -- installation. Carry the same human branch through that exact variant.
 SELECT pg_get_functiondef('zasp_temporal74.context(text,text,text,text)'::regprocedure) INTO d;
 d:=replace(d,'FUNCTION zasp_temporal74.context(o text, w text, e text, r text)','FUNCTION zasp_temporal74.context_parent(o text, w text, e text, r text, parent_value jsonb)');
 needle:='SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'human context parent predecessor changed';END IF;
 d:=replace(d,needle,'rr:=jsonb_populate_record(NULL::public.zasp_security_agent_runs,parent_value);');
 d:=replace(d,'public.zasp_sa_manual_provenance(o,w,e,r)','zasp_temporal74.manual_parent(o,w,e,r,parent_value)');
 EXECUTE replace(d,'zasp_temporal74.authorize(','zasp_temporal74.service_current(');
 SELECT definition INTO STRICT d FROM zasp_temporal76.predecessor_functions WHERE signature='zasp_temporal74.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal74.fingerprint()','FUNCTION zasp_temporal76.executor74_fingerprint()');
 d:=replace(d,'pg_get_functiondef(p.oid)', $projection$CASE WHEN p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal76.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
 d:=replace(d,'pg_get_constraintdef(k.oid)',$projection$CASE WHEN k.conrelid='zasp_temporal74.run_owners'::regclass AND k.conname='run_owners_source_kind_check' THEN (SELECT definition FROM zasp_temporal76.predecessor_constraints WHERE signature='zasp_temporal74.run_owners.run_owners_source_kind_check') ELSE pg_get_constraintdef(k.oid) END$projection$);
 EXECUTE d;
END $executor$;
CREATE OR REPLACE FUNCTION zasp_temporal74.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal76.catalog_ready() THEN zasp_temporal76.executor74_fingerprint() ELSE NULL END
$fingerprint$;

DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal70.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal70','zasp_temporal76');
 d:=replace(d,'-- compatibility70 checksum','-- human76 checksum');
 d:=replace(d,'-- compatibility70 fingerprint','-- human76 fingerprint');
 d:=replace(d,'UNION ALL SELECT concat_ws(''|'',''saved''',$tracking$UNION ALL SELECT concat_ws('|','human-trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgrelid='public.zasp_security_agent_request_receipts'::regclass AND t.tgname='zasp_temporal76_capture'
 UNION ALL SELECT concat_ws('|','owner-policy',p.polrelid::regclass::text,p.polname,p.polpermissive,p.polcmd,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p WHERE p.polname='zasp_temporal76_owner' AND p.polrelid='public.zasp_security_agent_runs'::regclass
 UNION ALL SELECT concat_ws('|','executor-function',p.oid::regprocedure::text,p.proowner::regrole::text,COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.oid IN('zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.fingerprint()'::regprocedure)
 UNION ALL SELECT concat_ws('|','executor-constraint',k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k WHERE k.conrelid='zasp_temporal74.run_owners'::regclass AND k.conname='run_owners_source_kind_check'
 UNION ALL SELECT concat_ws('|','saved-constraint',signature,definition) FROM zasp_temporal76.predecessor_constraints
 UNION ALL SELECT concat_ws('|','saved'$tracking$);
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure signature FROM pg_proc WHERE pronamespace='zasp_temporal76'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal76 TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal76.api_ready(text,text),zasp_temporal76.family(text,text,text,text,text),zasp_temporal76.resource(jsonb) TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_temporal76.visible(text,text,text,text) TO PUBLIC;
