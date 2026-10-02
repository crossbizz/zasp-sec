-- Retained HTTP mutations keep their original actor/session/CAS checks. A
-- deferred constraint trigger binds the final displayed receipt before commit.
-- Delivery never repeats a mutation and never supplies execution authority.
CREATE TABLE zasp_temporal78.control_intents(LIKE zasp_temporal74.control_intents INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal78.control_intents ADD PRIMARY KEY(organization_id,workspace_id,environment_id,control_id),ADD UNIQUE(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key),ADD FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal78.run_owners;
CREATE TABLE zasp_temporal78.control_deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,control_id text NOT NULL,
 last_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,control_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,control_id) REFERENCES zasp_temporal78.control_intents);
CREATE INDEX pending_controls ON zasp_temporal78.control_deliveries(last_attempt_at,organization_id,workspace_id,environment_id,control_id) WHERE accepted_at IS NULL;
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['control_intents','control_deliveries'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal78.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal78.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
 END LOOP;
END $tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal78.control_intents FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

INSERT INTO zasp_temporal78.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'zasp_temporal74.record_control(text,text,text,text,text,text,text)'::regprocedure,'zasp_temporal74.decision_owner(zasp_temporal74.control_intents)'::regprocedure);
DO $copies$ DECLARE p record;d text;needle text;BEGIN
 FOR p IN SELECT * FROM zasp_temporal78.predecessor_functions WHERE signature IN('zasp_temporal74.record_control(text,text,text,text,text,text,text)','zasp_temporal74.decision_owner(zasp_temporal74.control_intents)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION 'finding control predecessor owner changed';END IF;
  d:=replace(p.definition,'zasp_temporal74.','zasp_temporal78.');
  EXECUTE replace(d,'security_agent_test_control','security_agent_finding_control');
 END LOOP;
 SELECT pg_get_functiondef('zasp_temporal78.authorize(text,text,text,text,bigint)'::regprocedure) INTO d;
 d:=replace(d,'FUNCTION zasp_temporal78.authorize(','FUNCTION zasp_temporal78.approval_service(');
 needle:=$old$zasp_temporal68.principal_ready('zasp_temporal_executor')$old$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding approval authority changed';END IF;
 EXECUTE replace(d,needle,$new$public.zasp_security_agent_principal_ready('zasp_security_agent_api')$new$);
 SELECT pg_get_functiondef('zasp_temporal78.context(text,text,text,text)'::regprocedure) INTO d;
 d:=replace(d,'FUNCTION zasp_temporal78.context(','FUNCTION zasp_temporal78.approval_context(');
 EXECUTE replace(d,'zasp_temporal78.authorize(','zasp_temporal78.approval_service(');
END $copies$;

CREATE FUNCTION zasp_temporal78.capture_control() RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE audit_value public.zasp_security_agent_audit%ROWTYPE;x zasp_temporal78.run_owners%ROWTYPE;rc public.zasp_security_agent_request_receipts%ROWTYPE;v zasp_temporal78.control_intents%ROWTYPE;ap public.zasp_security_agent_approvals%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;cv jsonb;BEGIN
 IF NEW.operation NOT IN('cancelSecurityAgentRun','decideSecurityAgentApproval') THEN RETURN NEW;END IF;
 SELECT * INTO audit_value FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.audit_id);
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,audit_value.run_id);
 IF x.run_id IS NULL THEN RETURN NEW;END IF;
 IF NOT zasp_temporal78.current_ready() OR NOT public.zasp_security_agent_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding decision capture unavailable';END IF;
 PERFORM zasp_temporal78.manager(x.organization_id,x.workspace_id,x.environment_id,NEW.principal_id);
 SELECT * INTO STRICT rc FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.principal_id,NEW.operation,NEW.idempotency_key) FOR SHARE;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 IF (rc.receipt_id,rc.audit_id,rc.correlation_id,rc.resource_id,rc.expected_version,rc.intent,rc.intent_digest) IS DISTINCT FROM(NEW.receipt_id,NEW.audit_id,NEW.correlation_id,NEW.resource_id,NEW.expected_version,NEW.intent,NEW.intent_digest)
  OR (rr.definition_id,rr.definition_version) IS DISTINCT FROM(x.definition_id,x.definition_version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding final decision identity changed';END IF;
 IF NEW.operation='cancelSecurityAgentRun' THEN
  IF rr.state<>'cancelled' OR rr.version<>rc.expected_version+1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding cancelled parent changed';END IF;
 ELSE
  cv:=zasp_temporal78.approval_context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  SELECT * INTO ap FROM public.zasp_security_agent_approvals WHERE(organization_id,workspace_id,environment_id,run_id,step_id,approval_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,rc.resource_id) FOR SHARE;
  IF cv->'definition'->>'autonomy' IS DISTINCT FROM 'supervised' OR ap.run_id IS NULL OR ap.approver_id IS DISTINCT FROM rc.principal_id OR ap.requester_id IS DISTINCT FROM rr.requested_by OR ap.requester_id=ap.approver_id OR ap.version<>rc.expected_version+1 OR ap.state IS DISTINCT FROM rc.response->>'state' OR ap.state NOT IN('approved','rejected','cancelled') OR ap.decided_at IS NULL OR ap.fresh_auth_at IS NULL OR ap.expires_at<=clock_timestamp() OR ap.plan_hash IS DISTINCT FROM rr.plan_hash
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p JOIN public.zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_temporal78.planning_jobs j USING(organization_id,workspace_id,environment_id,run_id) WHERE(p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.plan_hash)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,ap.plan_hash) AND p.plan_hash=digest(convert_to(p.plan::text,'UTF8'),'sha256') AND p.expires_at>clock_timestamp() AND b.deadline_at>clock_timestamp() AND b.stop_reason IS NULL AND j.state='admitted' AND zasp_temporal78.candidate_valid(j.result_value->'candidate',cv) AND zasp_temporal78.assignee(x.organization_id,x.workspace_id,x.environment_id,p.plan->'steps'->0->>'assignee_id'))
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding approval current proof rejected';END IF;
  IF rc.response-ARRAY['audit_id','correlation_id','receipt_id','replayed'] IS DISTINCT FROM zasp_temporal78.approval_public(zasp_temporal78.approval(x.organization_id,x.workspace_id,x.environment_id,ap.approval_id,rc.principal_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding approval committed display changed';END IF;
 END IF;
 PERFORM zasp_temporal78.record_control(x.organization_id,x.workspace_id,x.environment_id,x.run_id,rc.principal_id,rc.operation,rc.idempotency_key);
 SELECT * INTO STRICT v FROM zasp_temporal78.control_intents WHERE(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key)=(x.organization_id,x.workspace_id,x.environment_id,rc.principal_id,rc.operation,rc.idempotency_key);
 PERFORM zasp_temporal78.decision_owner(v);
 INSERT INTO zasp_temporal78.control_deliveries(organization_id,workspace_id,environment_id,control_id) VALUES(v.organization_id,v.workspace_id,v.environment_id,v.control_id);
 RETURN NEW;
END $capture$;
CREATE CONSTRAINT TRIGGER zasp_temporal78_control_capture AFTER INSERT ON public.zasp_security_agent_request_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION zasp_temporal78.capture_control();

CREATE FUNCTION zasp_temporal78.control_value(v zasp_temporal78.control_intents) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $value$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;terminal_value boolean:=false;BEGIN
 x:=zasp_temporal78.decision_owner(v);
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal78.start_deliveries WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AND accepted_at IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding control start proof unavailable';END IF;
 IF EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);terminal_value:=NOT zasp_temporal73.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal78.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);terminal_value:=NOT zasp_temporal73.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 END IF;
 RETURN jsonb_build_object('control_id',v.control_id,'kind',v.kind,'terminal',terminal_value,'start',jsonb_build_object('ref',jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id),'definition_version',x.definition_version,'input_digest',x.input_digest));
END $value$;

CREATE FUNCTION zasp_temporal78.pending_controls() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
DECLARE v zasp_temporal78.control_intents%ROWTYPE;items jsonb:='[]';BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding control delivery unavailable';END IF;
 FOR v IN SELECT c.* FROM zasp_temporal78.control_deliveries d JOIN zasp_temporal78.control_intents c USING(organization_id,workspace_id,environment_id,control_id) JOIN zasp_temporal78.start_deliveries s USING(organization_id,workspace_id,environment_id,run_id)
  WHERE d.accepted_at IS NULL AND s.accepted_at IS NOT NULL ORDER BY d.last_attempt_at,d.organization_id,d.workspace_id,d.environment_id,d.control_id LIMIT 5 LOOP
  UPDATE zasp_temporal78.control_deliveries SET last_attempt_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,control_id)=(v.organization_id,v.workspace_id,v.environment_id,v.control_id) AND accepted_at IS NULL;
  items:=items||jsonb_build_array(zasp_temporal78.control_value(v));
 END LOOP;
 RETURN items;
END $pending$;

CREATE FUNCTION zasp_temporal78.accept_control(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $accept$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;v zasp_temporal78.control_intents%ROWTYPE;t timestamptz;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding control acceptance unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','control_id']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding control acceptance shape rejected';END IF;
 x:=zasp_temporal78.start_identity(q-'control_id');
 SELECT * INTO STRICT v FROM zasp_temporal78.control_intents WHERE(organization_id,workspace_id,environment_id,run_id,control_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'control_id');
 PERFORM zasp_temporal78.control_value(v);
 UPDATE zasp_temporal78.control_deliveries SET accepted_at=COALESCE(accepted_at,clock_timestamp()) WHERE(organization_id,workspace_id,environment_id,control_id)=(v.organization_id,v.workspace_id,v.environment_id,v.control_id) RETURNING accepted_at INTO t;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding control delivery absent';END IF;
 RETURN jsonb_build_object('control_id',v.control_id,'workflow_id',x.workflow_id,'accepted_at',to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $accept$;
