-- Transactional decision outbox. Delivery is not execution/cleanup evidence.
CREATE TABLE zasp_temporal74.control_intents(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 control_id text NOT NULL,kind text NOT NULL CHECK(kind IN('approval','cancel')),
 actor_id text NOT NULL,operation text NOT NULL CHECK(operation IN('cancelSecurityAgentRun','decideSecurityAgentApproval')),
 idempotency_key text NOT NULL,resource_id text NOT NULL,expected_version bigint NOT NULL,
 receipt_id text NOT NULL,audit_id text NOT NULL,response_digest bytea NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,control_id),
 UNIQUE(organization_id,workspace_id,environment_id,actor_id,operation,idempotency_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal74.run_owners);
CREATE TABLE zasp_temporal74.control_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,control_id text NOT NULL,
 accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,control_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,control_id) REFERENCES zasp_temporal74.control_intents);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['control_intents','control_receipts'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal74.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal74.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal74.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;

CREATE FUNCTION zasp_temporal74.record_control(o text,w text,e text,r text,actor_value text,operation_value text,key_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $record$
DECLARE rc public.zasp_security_agent_request_receipts%ROWTYPE;kind_value text;id_value text;
BEGIN
 SELECT * INTO STRICT rc FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor_value,operation_value,key_value);
 IF NOT COALESCE(operation_value IN('cancelSecurityAgentRun','decideSecurityAgentApproval') AND rc.response->>'state' IN('approved','rejected','cancelled'),false) OR (CASE WHEN operation_value='cancelSecurityAgentRun' THEN rc.response->>'id' ELSE rc.response->>'run_id' END) IS DISTINCT FROM r THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test decision receipt rejected';END IF;
 kind_value:=CASE rc.response->>'state' WHEN 'approved' THEN 'approval' ELSE 'cancel' END;
 id_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_control',r||chr(31)||rc.receipt_id);
 INSERT INTO zasp_temporal74.control_intents VALUES(o,w,e,r,id_value,kind_value,actor_value,operation_value,key_value,rc.resource_id,rc.expected_version,rc.receipt_id,rc.audit_id,digest(convert_to(rc.response::text,'UTF8'),'sha256')) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal74.control_intents WHERE (organization_id,workspace_id,environment_id,run_id,control_id,kind,actor_id,operation,idempotency_key,resource_id,expected_version,receipt_id,audit_id,response_digest)=(o,w,e,r,id_value,kind_value,actor_value,operation_value,key_value,rc.resource_id,rc.expected_version,rc.receipt_id,rc.audit_id,digest(convert_to(rc.response::text,'UTF8'),'sha256'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test decision replay changed';END IF;
END $record$;

INSERT INTO zasp_temporal74.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid='public.zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)'::regprocedure;
DO $copy$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal74.predecessor_functions WHERE signature='zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)';
 d:=replace(d,'FUNCTION public.zasp_security_agent_cancel_run(','FUNCTION zasp_temporal74.cancel_core(');
 -- Installed58 added its exact export-family exception. Retain every other
 -- installed cancellation predicate and the63 manual response projection.
 needle:='IF NOT FOUND OR EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value) AND NOT (effect.action_key=''create_evidence_export'' AND EXISTS(SELECT 1 FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.input_digest,l.export_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.input_digest,effect.outcome_id)))) THEN';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'single-test cancellation predecessor changed';END IF;
 d:=replace(d,needle,'IF NOT FOUND THEN');
 needle:='PERFORM public.zasp_sa_export_cancel_child(organization_value,workspace_value,environment_value,run_value);';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'single-test cancellation export predecessor changed';END IF;
 EXECUTE replace(d,needle,'');
END $copy$;

CREATE FUNCTION zasp_temporal74.cancel(o text,w text,e text,r text,actor_value text,key_value text,expected_version bigint,audit_value text,correlation_value text,receipt_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cancel$
DECLARE result_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test cancellation isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test cancellation authority rejected';END IF;
 IF NOT zasp_temporal74.is_owned(o,w,e,r) THEN RETURN NULL;END IF;
 PERFORM zasp_temporal74.manager(o,w,e,actor_value);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test cancellation parent unavailable';END IF;
 -- The committed cancelled state fences fresh planning/dispatch/invocation.
 -- Existing effects, leases-free journals, budgets and debt are not deleted.
 result_value:=zasp_temporal74.cancel_core(o,w,e,r,actor_value,key_value,expected_version,audit_value,correlation_value,receipt_value);
 PERFORM zasp_temporal74.record_control(o,w,e,r,actor_value,'cancelSecurityAgentRun',key_value);
 PERFORM zasp_temporal74.manager(o,w,e,actor_value);
 IF NOT zasp_temporal74.api_ready('-- test74 checksum','-- test74 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test cancellation authority changed';END IF;
 RETURN result_value;
END $cancel$;

CREATE FUNCTION zasp_temporal74.decision_owner(v zasp_temporal74.control_intents) RETURNS zasp_temporal74.run_owners LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $decision$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;
BEGIN
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(v.organization_id,v.workspace_id,v.environment_id,v.run_id);
 IF v.control_id IS DISTINCT FROM public.zasp_discovery_canonical_id(v.organization_id,v.workspace_id,v.environment_id,'security_agent_test_control',v.run_id||chr(31)||v.receipt_id)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_request_receipts rc JOIN public.zasp_security_agent_audit a USING(organization_id,workspace_id,environment_id,audit_id)
   WHERE (rc.organization_id,rc.workspace_id,rc.environment_id,rc.principal_id,rc.operation,rc.idempotency_key,rc.resource_id,rc.expected_version,rc.receipt_id,rc.audit_id)=(v.organization_id,v.workspace_id,v.environment_id,v.actor_id,v.operation,v.idempotency_key,v.resource_id,v.expected_version,v.receipt_id,v.audit_id)
    AND digest(convert_to(rc.response::text,'UTF8'),'sha256')=v.response_digest AND rc.intent_digest=digest(convert_to(rc.intent::text,'UTF8'),'sha256')
    AND (a.run_id,a.actor_id,a.event_digest,a.correlation_id)=(v.run_id,v.actor_id,rc.intent_digest,rc.correlation_id)
    AND rc.response->>'audit_id'=v.audit_id AND rc.response->>'receipt_id'=v.receipt_id AND rc.response->>'correlation_id'=rc.correlation_id AND rc.response->'version'=to_jsonb(v.expected_version+1) AND rc.response->'replayed'='false'::jsonb
    AND v.kind=CASE rc.response->>'state' WHEN 'approved' THEN 'approval' ELSE 'cancel' END
    AND (v.operation='cancelSecurityAgentRun' AND rc.response->>'state'='cancelled' AND rc.response->>'id'=v.run_id AND v.resource_id=v.run_id
     AND a.event_kind='run_cancelled' AND a.step_id IS NULL AND a.approval_id IS NULL
     AND rc.intent=jsonb_build_object('run_id',v.run_id,'expected_version',v.expected_version)
     AND a.body=jsonb_build_object('run_id',v.run_id,'prior_state',a.body->>'prior_state','version',v.expected_version+1) AND a.body->>'prior_state' IN('queued','planning','waiting_approval','running','verifying')
     OR v.operation='decideSecurityAgentApproval' AND rc.response->>'state' IN('approved','rejected','cancelled') AND rc.response->>'id'=v.resource_id AND rc.response->>'run_id'=v.run_id AND rc.response->>'step_id'=x.step_id
     AND (a.event_kind,a.step_id,a.approval_id)=('approval_decided',x.step_id,v.resource_id)
     AND rc.intent=jsonb_build_object('approval_id',v.resource_id,'expected_version',v.expected_version,'decision',rc.response->>'state')
     AND a.body=jsonb_build_object('approval_id',v.resource_id,'run_id',v.run_id,'decision',rc.response->>'state','version',v.expected_version+1)))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test control proof unavailable';END IF;
 RETURN x;
END $decision$;

CREATE FUNCTION zasp_temporal74.control_value(v zasp_temporal74.control_intents) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $value$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;terminal_value boolean:=false;
BEGIN
 x:=zasp_temporal74.decision_owner(v);
 IF NOT EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.run_id)=(v.organization_id,v.workspace_id,v.environment_id,v.run_id) AND accepted_at IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test control start proof unavailable';END IF;
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);terminal_value:=NOT zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal74.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);terminal_value:=NOT zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 END IF;
 RETURN jsonb_build_object('control_id',v.control_id,'kind',v.kind,'terminal',terminal_value,'start',jsonb_build_object('ref',jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id),'definition_version',x.definition_version,'input_digest',x.input_digest));
END $value$;

CREATE FUNCTION zasp_temporal74.pending_controls() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
DECLARE v zasp_temporal74.control_intents%ROWTYPE;items jsonb:='[]';
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test control delivery rejected';END IF;
 FOR v IN SELECT c.* FROM zasp_temporal74.control_intents c JOIN zasp_temporal74.start_deliveries s USING(organization_id,workspace_id,environment_id,run_id) LEFT JOIN zasp_temporal74.control_receipts a USING(organization_id,workspace_id,environment_id,control_id) WHERE s.accepted_at IS NOT NULL AND a.control_id IS NULL ORDER BY c.organization_id,c.workspace_id,c.environment_id,c.control_id LIMIT 100 LOOP
  items:=items||jsonb_build_array(zasp_temporal74.control_value(v));
 END LOOP;
 RETURN items;
END $pending$;

CREATE FUNCTION zasp_temporal74.accept_control(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $accept$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;v zasp_temporal74.control_intents%ROWTYPE;t timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test control acceptance rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','control_id']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test control acceptance shape rejected';END IF;
 x:=zasp_temporal74.start_identity(q-'control_id');
 SELECT * INTO STRICT v FROM zasp_temporal74.control_intents WHERE (organization_id,workspace_id,environment_id,run_id,control_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'control_id');
 PERFORM zasp_temporal74.control_value(v);
 INSERT INTO zasp_temporal74.control_receipts(organization_id,workspace_id,environment_id,control_id) VALUES(v.organization_id,v.workspace_id,v.environment_id,v.control_id) ON CONFLICT DO NOTHING;
 SELECT accepted_at INTO STRICT t FROM zasp_temporal74.control_receipts WHERE (organization_id,workspace_id,environment_id,control_id)=(v.organization_id,v.workspace_id,v.environment_id,v.control_id);
 RETURN jsonb_build_object('control_id',v.control_id,'workflow_id',x.workflow_id,'accepted_at',to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $accept$;
