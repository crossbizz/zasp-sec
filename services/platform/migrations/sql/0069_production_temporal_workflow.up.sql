-- Composition authority is additive. Exact68 remains the effect authority.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal69 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal69 FROM PUBLIC;
CREATE TABLE zasp_temporal69.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL);
CREATE TABLE zasp_temporal69.predecessor_functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl text NOT NULL);
CREATE TABLE zasp_temporal69.stops(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 stop_id text NOT NULL UNIQUE,reason text NOT NULL CHECK(reason IN('workflow_cancelled','workflow_deadline','workflow_failed')),
 start_event_id text NOT NULL,input_digest text NOT NULL,definition_version bigint NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id));
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['registration','predecessor_functions','stops'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal69.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal69.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal69.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal69.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal69.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
INSERT INTO zasp_temporal69.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN('zasp_temporal68.progress_transition(text,text,jsonb)'::regprocedure,'zasp_temporal68.test_stop(jsonb)'::regprocedure);

CREATE FUNCTION zasp_temporal69.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN COALESCE(c='-- workflow69 checksum' AND f='-- workflow69 fingerprint'
 AND zasp_temporal68.ready('-- executor68 checksum','-- executor68 fingerprint')
 AND (SELECT count(*)=1 FROM zasp_temporal69.registration)
 AND EXISTS(SELECT 1 FROM zasp_temporal69.registration WHERE checksum=c AND fingerprint=f)
 AND zasp_temporal69.fingerprint()=f,false); END
$ready$;
CREATE FUNCTION zasp_temporal69.current_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal69.ready('-- workflow69 checksum','-- workflow69 fingerprint')
$ready$;

-- The retained start is bound to the original product trigger, independently
-- of Temporal's history retention. Bodies never cross this read boundary.
CREATE FUNCTION zasp_temporal69.principal_ready(a text) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $principal$
 SELECT a IN('zasp_temporal_executor','zasp_temporal_compensation') AND zasp_temporal69.current_ready() AND zasp_temporal68.principal_ready(a)
$principal$;

CREATE FUNCTION zasp_temporal69.inspect(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $inspect$
DECLARE o text;w text;e text;r text;k text;v jsonb;command zasp_temporal65.commands%ROWTYPE;markers jsonb;effects_value jsonb;terminal_value boolean;cleanup_value boolean;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='workflow read requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal69.current_ready() OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workflow principal unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest']) OR octet_length(q::text)>4096
 OR NOT COALESCE(q->>'input_digest'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workflow request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workflow scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 v:=zasp_temporal68.status(q-'input_digest');
 SELECT * INTO command FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id,kind)=(o,w,e,r,'start');
 IF NOT FOUND OR command.execution_owner<>'temporal' OR command.input_digest IS DISTINCT FROM q->>'input_digest' OR to_jsonb(command.definition_version) IS DISTINCT FROM q->'definition_version'
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r) AND encode(t.trigger_digest,'hex')=command.input_digest)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='workflow retained start rejected';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',t.device_id,'source_digest','sha256:'||encode(t.envelope_digest,'hex'),'expires_at',zasp_temporal68.cleanup_marker(t)->'expires_at') ORDER BY t.device_id),'[]') INTO markers
 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.phase)=(o,w,e,r,'cleanup') AND t.state<>'planned';
 SELECT COALESCE(jsonb_agg(jsonb_build_object('step_id',x->'step_id','state',x->'state','action_key',x->'action_key','effect_key',x->'effect_key','generation',x->'generation') ORDER BY x->>'step_id'),'[]') INTO effects_value FROM jsonb_array_elements(v->'effects') x;
 terminal_value:=v->>'run_state' IN('cancelled','needs_human','failed','inconclusive','contained','remediated');
 cleanup_value:=EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t JOIN zasp_temporal68.effects f USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.phase)=(o,w,e,r,'apply') AND t.state IN('stored','verified') AND f.state<>'cleaned');
 RETURN jsonb_build_object('start',q,'start_event_id',command.event_id,'run_state',v->'run_state','run_version',v->'run_version','admitted',v->'admitted','planning_state',v->'planning'->'state','projection',v->'projection','effects',effects_value,'cleanup_markers',markers,'terminal',terminal_value,'cleanup_required',cleanup_value);
END $inspect$;

CREATE FUNCTION zasp_temporal69.inspect_message(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $message$
DECLARE c zasp_temporal65.commands%ROWTYPE;s zasp_temporal65.commands%ROWTYPE;v jsonb;
BEGIN
 IF NOT zasp_temporal69.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workflow message principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','event_id','decision_id','kind']) OR octet_length(q::text)>4096 OR q->>'kind' NOT IN('approval','cancel') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workflow message rejected';END IF;
 SELECT * INTO c FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id,event_id,decision_id,kind,execution_owner)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'event_id',q->>'decision_id',q->>'kind','temporal');
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts rr JOIN public.zasp_security_agent_audit a ON (a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.audit_id) WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.receipt_id,a.run_id)=(c.organization_id,c.workspace_id,c.environment_id,c.decision_id,c.run_id) AND rr.intent_digest=digest(convert_to(rr.intent::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='workflow committed decision absent';END IF;
 SELECT * INTO STRICT s FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id,kind)=(c.organization_id,c.workspace_id,c.environment_id,c.run_id,'start');
 RETURN zasp_temporal69.inspect(jsonb_build_object('organization_id',s.organization_id,'workspace_id',s.workspace_id,'environment_id',s.environment_id,'run_id',s.run_id,'definition_version',s.definition_version,'input_digest',s.input_digest));
END $message$;

-- Copy the reviewed transition and force only this private worker-stop path.
-- Its public state, audit, version and approval handling remain the same.
DO $stop_copy$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal69.predecessor_functions WHERE signature='zasp_temporal68.progress_transition(text,text,jsonb)';
 d:=replace(d,'FUNCTION zasp_temporal68.progress_transition(','FUNCTION zasp_temporal69.stop_transition(');
 needle:=' IF op=''stop'' AND NOT blocked THEN blocked:=zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r);END IF;';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'workflow stop predecessor rejected';END IF;
 d:=replace(d,needle,' IF op=''stop'' THEN blocked:=true;END IF;');
 EXECUTE d;
END $stop_copy$;

-- The existing reserved-test gate only recognizes live requester revocation.
-- This private copy also recognizes the authenticated worker stop in this same
-- transaction. All child, journal, snapshot, usage and replay checks stay exact.
DO $test_stop_copy$ DECLARE d text;needle text;replacement text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal69.predecessor_functions WHERE signature='zasp_temporal68.test_stop(jsonb)';
 d:=replace(d,'FUNCTION zasp_temporal68.test_stop(','FUNCTION zasp_temporal69.stop_test(');
 needle:='NOT zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'workflow reserved-stop predecessor rejected';END IF;
 replacement:=$gate$NOT (zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r) OR zasp_temporal68.principal_ready('zasp_temporal_compensation') AND EXISTS(
  SELECT 1 FROM zasp_temporal69.stops ws JOIN zasp_temporal65.commands c ON (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.kind,c.event_id,c.input_digest,c.definition_version,c.execution_owner)=(ws.organization_id,ws.workspace_id,ws.environment_id,ws.run_id,'start',ws.start_event_id,ws.input_digest,ws.definition_version,'temporal')
  JOIN public.zasp_security_agent_runs rr ON (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(ws.organization_id,ws.workspace_id,ws.environment_id,ws.run_id)
  WHERE (ws.organization_id,ws.workspace_id,ws.environment_id,ws.run_id)=(o,w,e,r) AND rr.state IN('cancelled','needs_human','failed','inconclusive','contained','remediated') AND rr.completed_at IS NOT NULL))$gate$;
 EXECUTE replace(d,needle,replacement);
END $test_stop_copy$;

CREATE FUNCTION zasp_temporal69.stop(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $stop$
DECLARE v jsonb;o text;w text;e text;r text;s text;stopped zasp_temporal69.stops%ROWTYPE;request_value jsonb;f record;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='workflow stop principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','reason']) OR NOT COALESCE(q->>'reason' IN('workflow_cancelled','workflow_deadline','workflow_failed'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='workflow stop reason rejected';END IF;
 v:=zasp_temporal69.inspect(q-'reason');o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 SELECT * INTO stopped FROM zasp_temporal69.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  IF stopped.input_digest IS DISTINCT FROM q->>'input_digest' OR to_jsonb(stopped.definition_version) IS DISTINCT FROM q->'definition_version' OR stopped.start_event_id IS DISTINCT FROM v->>'start_event_id' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='workflow stop identity changed';END IF;
  RETURN to_jsonb(stopped);
 END IF;
 IF NOT (v->>'terminal')::boolean THEN
  IF NOT (v->>'admitted')::boolean THEN
   IF v->>'planning_state' IS NOT NULL THEN
    PERFORM zasp_temporal68.plan((q-ARRAY['reason','input_digest'])||jsonb_build_object('operation','reconcile','payload','{}'::jsonb));
   ELSE
    UPDATE public.zasp_security_agent_runs SET state='cancelled',version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,r,'queued');
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='workflow queued stop changed';END IF;
   END IF;
  ELSE
   s:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'1');
   request_value:=(q-ARRAY['reason','input_digest','definition_version'])||jsonb_build_object('step_id',s,'operation','stop','actor_id',session_user,'run_version',v->'run_version','approval_version',1,'fresh_auth_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
   PERFORM zasp_temporal69.stop_transition(NULL,NULL,request_value);
  END IF;
 END IF;
 INSERT INTO zasp_temporal69.stops VALUES(o,w,e,r,public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_workflow_stop',r),q->>'reason',v->>'start_event_id',q->>'input_digest',(q->>'definition_version')::bigint) RETURNING * INTO stopped;
 -- A sent linked test keeps unknown/settled journal evidence. Never resend.
 FOR f IN SELECT step_id FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,'run_test') AND state IN('reserved','started','unknown') LOOP
  PERFORM zasp_temporal69.stop_test((q-ARRAY['reason','input_digest','definition_version'])||jsonb_build_object('step_id',f.step_id,'generation',1,'operation','stop','payload','{}'::jsonb));
 END LOOP;
 PERFORM zasp_temporal69.inspect(q-'reason');
 RETURN to_jsonb(stopped);
END $stop$;

-- Copy the complete existing catalog fingerprint recipe for this new schema.
-- The compiler test derives and compares the pin before registration.
DO $fingerprint$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal68.fingerprint()'::regprocedure) INTO d;
 d:=replace(d,'zasp_temporal68','zasp_temporal69');
 d:=replace(d,'-- executor68 checksum','-- workflow69 checksum');
 d:=replace(d,'-- executor68 fingerprint','-- workflow69 fingerprint');
 EXECUTE d;
END $fingerprint$;
DO $functions$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal69'::regnamespace LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $functions$;
GRANT USAGE ON SCHEMA zasp_temporal69 TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal69.ready(text,text),zasp_temporal69.inspect(jsonb) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal69.inspect_message(jsonb) TO zasp_temporal_executor;
GRANT EXECUTE ON FUNCTION zasp_temporal69.principal_ready(text) TO zasp_temporal_executor,zasp_temporal_compensation;
GRANT EXECUTE ON FUNCTION zasp_temporal69.stop(jsonb) TO zasp_temporal_compensation;
