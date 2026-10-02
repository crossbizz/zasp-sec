CREATE TABLE zasp_temporal74.start_deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 last_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs);
ALTER TABLE zasp_temporal74.start_deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal74.start_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal74.start_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal74.start_deliveries USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

CREATE FUNCTION zasp_temporal74.unresolved(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $unresolved$
 SELECT zasp_temporal73.unresolved(o,w,e,r)
 OR EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.settled_at IS NULL AND x.released_at IS NULL)
 OR EXISTS(SELECT 1 FROM zasp_temporal74.effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r) AND x.state IN('started','unknown'))
 OR EXISTS(SELECT 1 FROM zasp_temporal74.invocations x JOIN zasp_temporal74.run_owners a USING(organization_id,workspace_id,environment_id,test_run_id) WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,x.state)=(o,w,e,r,'started'))
$unresolved$;

-- All-owner visibility belongs to the existing non-login accounting role.
-- Exclude the incoming row once; a queued row being admitted already exists.
CREATE FUNCTION zasp_temporal74.capacity(o text,w text,e text,d text,incoming text) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $capacity$
 WITH occupied AS (
  SELECT r.*,b.run_id budget_id,b.concurrency_limit,b.stop_reason,zasp_temporal74.unresolved(r.organization_id,r.workspace_id,r.environment_id,r.run_id) uncertain
  FROM public.zasp_security_agent_runs r LEFT JOIN public.zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
  WHERE r.organization_id=o AND r.run_id<>incoming AND r.state<>'simulated'
 ), active AS (
  SELECT *,uncertain OR state IN('planning','running','verifying','waiting_approval') OR budget_id IS NOT NULL AND stop_reason IS NULL AND state IN('queued','contained') org_active FROM occupied
 ) SELECT jsonb_build_object('definition_count',count(*) FILTER(WHERE (workspace_id,environment_id,definition_id)=(w,e,d) AND (uncertain OR state IN('queued','planning','waiting_approval','running','verifying','contained'))),
  'organization_count',count(*) FILTER(WHERE org_active),'organization_limit',min(concurrency_limit) FILTER(WHERE org_active)) FROM active
$capacity$;

CREATE FUNCTION zasp_temporal74.admission_capacity(v jsonb) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $capacity$
DECLARE b integer;current_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test shared admission isolation rejected';END IF;
 IF NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='single-test shared admission catalog unavailable';END IF;
 -- Retained claimers can already hold the parent. Never wait in inverse order.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||(v->>'organization_id'),0)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test shared admission busy';END IF;
 SELECT (body->>'concurrency_limit')::integer INTO b FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'definition_id',(v->>'definition_version')::bigint) AND deleted_at IS NULL FOR SHARE;
 current_value:=zasp_temporal74.capacity(v->>'organization_id',v->>'workspace_id',v->>'environment_id',v->>'definition_id',v->>'run_id');
 IF b IS NULL OR b<1 OR (current_value->>'definition_count')::bigint>=b OR (current_value->>'organization_count')::bigint>=least(b,COALESCE((current_value->>'organization_limit')::integer,b)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test shared admission capacity unavailable';END IF;
END $capacity$;

CREATE FUNCTION zasp_temporal74.start_identity(q jsonb) RETURNS zasp_temporal74.run_owners LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $identity$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;k text;
BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest']) OR octet_length(q::text)>4096 OR q->>'input_digest'!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test start rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test start scope rejected';END IF;END LOOP;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,input_digest)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'input_digest') AND to_jsonb(definition_version)=q->'definition_version';
 IF x.run_id IS NULL OR x.workflow_id IS DISTINCT FROM 'security-agent-test/v1/'||x.organization_id||'/'||x.workspace_id||'/'||x.environment_id||'/'||x.run_id
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id,t.trigger_version,t.trigger_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_id,x.trigger_id,x.trigger_version,decode(x.input_digest,'hex')))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test durable start changed';END IF;
 RETURN x;
END $identity$;

CREATE FUNCTION zasp_temporal74.client_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $client_ready$
 SELECT zasp_temporal74.ready(c,f) AND (zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation'))
$client_ready$;

CREATE FUNCTION zasp_temporal74.planning_state(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $planning_state$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;j zasp_temporal74.planning_jobs%ROWTYPE;k text;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test planning read rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version']) OR octet_length(q::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test planning read shape rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test planning read scope rejected';END IF;END LOOP;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id') AND to_jsonb(definition_version)=q->'definition_version';
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test planning owner changed';END IF;
 SELECT * INTO j FROM zasp_temporal74.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id,definition_version)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_version);
 IF NOT FOUND THEN RETURN 'null'::jsonb;END IF;
 RETURN to_jsonb(j);
END $planning_state$;

CREATE FUNCTION zasp_temporal74.pending() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
DECLARE candidate record;x jsonb;items jsonb:='[]';
BEGIN
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test start consumer rejected';END IF;
 -- This consumes already-committed starts, not product source selection. The
 -- attempt timestamp rotates ineligible retained rows without claiming them.
 FOR candidate IN
  WITH starts AS (
   SELECT organization_id,workspace_id,environment_id,run_id FROM zasp_temporal65.commands WHERE kind='start' AND execution_owner='legacy' AND accepted_at IS NULL
   UNION SELECT organization_id,workspace_id,environment_id,run_id FROM zasp_temporal73.commands WHERE kind='start' AND revision=1
  ) SELECT s.* FROM starts s LEFT JOIN zasp_temporal74.start_deliveries d USING(organization_id,workspace_id,environment_id,run_id)
  WHERE d.accepted_at IS NULL ORDER BY d.last_attempt_at NULLS FIRST,s.organization_id,s.workspace_id,s.environment_id,s.run_id LIMIT 100
 LOOP
  -- Admission takes this lock before run rows. Never retain a delivery row
  -- while waiting for the organization, including across candidates in a batch.
  IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||candidate.organization_id,0)) THEN CONTINUE;END IF;
  INSERT INTO zasp_temporal74.start_deliveries(organization_id,workspace_id,environment_id,run_id) VALUES(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id)
  ON CONFLICT(organization_id,workspace_id,environment_id,run_id) DO UPDATE SET last_attempt_at=clock_timestamp();
  BEGIN
   x:=zasp_temporal74.takeover(candidate.organization_id,candidate.workspace_id,candidate.environment_id,candidate.run_id);
   IF x IS NOT NULL AND x<>'null'::jsonb THEN
    items:=items||jsonb_build_array(jsonb_build_object('ref',jsonb_build_object('organization_id',x->'organization_id','workspace_id',x->'workspace_id','environment_id',x->'environment_id','run_id',x->'run_id'),'definition_version',x->'definition_version','input_digest',x->'input_digest'));
   END IF;
  EXCEPTION WHEN SQLSTATE '42501' OR SQLSTATE '40001' OR SQLSTATE '55P03' THEN NULL;
  END;
 END LOOP;
 RETURN items;
END $pending$;

CREATE FUNCTION zasp_temporal74.accept_start(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $accept$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;accepted timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test start acceptance rejected';END IF;
 x:=zasp_temporal74.start_identity(q);
 INSERT INTO zasp_temporal74.start_deliveries(organization_id,workspace_id,environment_id,run_id,accepted_at) VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,clock_timestamp())
 ON CONFLICT(organization_id,workspace_id,environment_id,run_id) DO UPDATE SET accepted_at=COALESCE(zasp_temporal74.start_deliveries.accepted_at,EXCLUDED.accepted_at) RETURNING accepted_at INTO accepted;
 RETURN jsonb_build_object('workflow_id',x.workflow_id,'accepted_at',to_char(accepted AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $accept$;

CREATE TABLE zasp_temporal74.stops(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 definition_version bigint NOT NULL,input_digest text NOT NULL,reason text NOT NULL CHECK(reason IN('workflow_cancelled','workflow_deadline','workflow_failed')),
 proof jsonb NOT NULL,audit_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal74.run_owners(organization_id,workspace_id,environment_id,run_id));
ALTER TABLE zasp_temporal74.stops OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal74.stops ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal74.stops FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal74.stops USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.stops FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

-- This is a cancelled-child proof, never a native execution receipt. Keep the
-- established public failure projection while binding the unsent74 stop audit.
CREATE FUNCTION zasp_temporal74.cancelled_link(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $cancelled$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;t zasp_temporal74.stops%ROWTYPE;v jsonb;p jsonb;b bytea;receipt jsonb;
BEGIN
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO STRICT t FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF t.proof->>'kind' IS DISTINCT FROM 'admitted' OR t.proof->>'effect_state' IS DISTINCT FROM 'reserved' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test cancellation link unavailable';END IF;
 v:=zasp_temporal74.evidence_snapshot(o,w,e,r,x.step_id);
 p:=jsonb_build_object('schema_version','security-agent-test-verification-v1','outcome','cancelled','reason','test_run_cancelled');
 PERFORM public.zasp_production_security_agent_existing_tests_validate_proof(v,p,false);
 b:=convert_to(p::text,'UTF8');
 receipt:=jsonb_build_object('run_id',r,'step_id',x.step_id,'state',t.proof->>'parent_state','step_state','cancelled','effect_state','known_failure','outcome','cancelled','reason','test_run_cancelled','proof_sha256',encode(digest(b,'sha256'),'hex'),'reconcile_version',2);
 RETURN jsonb_build_object('kind','stopped_before_dispatch','organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',x.step_id,'test_run_id',x.test_run_id,'effect_key',t.proof->'effect_key','stop_audit_id',t.audit_id,'stop_proof',t.proof,'snapshot',v,'proof',p,'proof_hex',encode(b,'hex'),'receipt',receipt);
END $cancelled$;

CREATE FUNCTION zasp_temporal74.queued_absent(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $absent$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal74.run_owners x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r)
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,x.test_run_id))
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal74.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id))
  AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id))
  AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id)))
$absent$;

CREATE FUNCTION zasp_temporal74.stop_evidence(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE t zasp_temporal74.stops%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;x zasp_temporal74.run_owners%ROWTYPE;parent_valid boolean;
BEGIN
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO t FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,x.test_run_id);
 parent_valid:=CASE WHEN public.zasp_red_team_principal_ready('zasp_red_team_worker') THEN zasp_temporal74.delivery_parent_matches(zasp_temporal74.delivery_message(o,w,e,r)) ELSE rr.run_id IS NOT NULL AND rr.state IN('cancelled','failed','inconclusive','needs_human') AND rr.completed_at IS NOT NULL AND rr.lease_owner IS NULL AND rr.lease_token IS NULL AND rr.lease_expires_at IS NULL AND rr.state=t.proof->>'parent_state' AND rr.last_error_code=t.proof->>'parent_reason' END;
 IF t.run_id IS NULL OR (t.definition_version,t.input_digest) IS DISTINCT FROM(x.definition_version,x.input_digest)
  OR t.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_single_test_stop',r)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,audit_id,correlation_id,event_kind,body)=(o,w,e,r,t.audit_id,t.audit_id,'temporal_test_stopped',jsonb_build_object('reason',t.reason,'definition_version',t.definition_version,'input_digest',t.input_digest,'proof',t.proof)) AND event_digest=digest(convert_to(body::text,'UTF8'),'sha256'))
  OR NOT COALESCE(parent_valid,false)
  OR NOT (CASE WHEN t.proof->>'kind'='admitted' AND t.proof->>'effect_state'='absent' THEN t.proof->'effect_key'='null'::jsonb AND zasp_sa_multistep_prior.closed(t.proof-'effect_key',ARRAY['kind','effect_state','parent_reason','parent_state']) ELSE zasp_sa_multistep_prior.closed(t.proof,CASE WHEN t.proof->>'kind'='admitted' THEN ARRAY['kind','effect_state','effect_key','parent_state','parent_reason'] ELSE ARRAY['kind','parent_state','parent_reason'] END) END)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test stop proof changed';END IF;
 IF t.proof->>'kind'='planning' THEN
  IF NOT zasp_temporal74.planning_terminal_valid(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test stopped planner changed';END IF;
 ELSIF t.proof->>'kind'='queued' THEN
  IF NOT zasp_temporal74.queued_absent(o,w,e,r) OR t.proof->>'parent_state' IS DISTINCT FROM 'cancelled' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test queued stop changed';END IF;
 ELSIF t.proof->>'kind'='admitted' THEN
  IF NOT COALESCE(t.proof->>'effect_state' IN('absent','reserved','started','unknown'),false)
   OR t.proof->>'effect_state'='absent' AND (f.run_id IS NOT NULL OR child.run_id IS NOT NULL OR t.proof->'effect_key' IS DISTINCT FROM 'null'::jsonb)
   OR t.proof->>'effect_state'<>'absent' AND (f.run_id IS NULL OR child.run_id IS NULL OR t.proof->>'effect_key' IS DISTINCT FROM f.effect_key OR f.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(o,w,e,r,x.step_id,1))
   OR t.proof->>'effect_state'='reserved' AND (f.state IS DISTINCT FROM 'stopped' OR f.started_at IS NOT NULL OR f.completed_at IS NULL OR child.state IS DISTINCT FROM 'cancelled' OR child.attempt IS DISTINCT FROM 0 OR child.completed_at IS NULL OR child.worker_id IS NOT NULL OR child.lease_token IS NOT NULL OR child.lease_expires_at IS NOT NULL OR EXISTS(SELECT 1 FROM zasp_temporal74.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id)) OR EXISTS(SELECT 1 FROM zasp_temporal68.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,x.test_run_id)) OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,x.step_id,'known_failure') AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL))
   OR t.proof->>'effect_state' IN('started','unknown') AND NOT COALESCE(f.state IN('started','unknown','verified'),false)
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test effect stop changed';END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test stop kind changed';END IF;
 IF t.proof->>'kind'='admitted' AND t.proof->>'effect_state'='reserved' THEN
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links l JOIN public.zasp_security_agent_effects m USING(organization_id,workspace_id,environment_id,run_id,step_id)
   WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.test_run_id,l.reconcile_state,l.reconcile_version,l.cancellation_outcome)=(o,w,e,r,x.step_id,x.test_run_id,'settled',2,'cancelled_before_execution')
    AND l.reconcile_worker IS NULL AND l.reconcile_token IS NULL AND l.reconcile_expires_at IS NULL AND l.cancellation_recorded_at IS NOT NULL
    AND l.reconcile_settlement=zasp_temporal74.cancelled_link(o,w,e,r) AND m.state='known_failure' AND m.result_digest=digest(decode(l.reconcile_settlement->>'proof_hex','hex'),'sha256')
    AND m.outcome_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_outcome',r||chr(31)||x.step_id))
   OR EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
   OR EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test cancellation link proof changed';END IF;
 END IF;
 RETURN jsonb_build_object('kind','stopped','reason',t.reason,'proof',t.proof,'audit_id',t.audit_id);
END $evidence$;

CREATE FUNCTION zasp_temporal74.cleanup(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cleanup$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal74.planning_jobs%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;t zasp_temporal74.stops%ROWTYPE;proof_value jsonb;evidence_value jsonb;audit_value text;body_value jsonb;request_value jsonb;link_value jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test cleanup authority rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','reason']) OR NOT COALESCE(q->>'reason' IN('terminal','workflow_cancelled','workflow_deadline','workflow_failed'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test cleanup request rejected';END IF;
 x:=zasp_temporal74.start_identity(q-'reason');
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  evidence_value:=zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 ELSE
  SELECT * INTO j FROM zasp_temporal74.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  SELECT * INTO t FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF t.run_id IS NULL AND j.state='needs_human' AND q->>'reason'='terminal' THEN
   IF NOT zasp_temporal74.planning_terminal_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test terminal cleanup proof rejected';END IF;
   evidence_value:=jsonb_build_object('kind','planning_terminal','run_id',x.run_id);
  ELSE
   IF t.run_id IS NULL THEN
    IF q->>'reason'='terminal' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test terminal cleanup lacks receipt';END IF;
    IF j.run_id IS NOT NULL AND j.state<>'admitted' THEN
     request_value:=(q-ARRAY['reason','input_digest'])||jsonb_build_object('operation','reconcile','payload','{}'::jsonb);
     PERFORM zasp_temporal74.plan(request_value);proof_value:=jsonb_build_object('kind','planning');
    ELSE
     SELECT * INTO f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
     IF j.run_id IS NULL THEN
      IF NOT zasp_temporal74.queued_absent(x.organization_id,x.workspace_id,x.environment_id,x.run_id) OR rr.state NOT IN('queued','cancelled') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test queued stop unavailable';END IF;
      IF rr.state='cancelled' THEN
       PERFORM zasp_temporal74.decision_owner(c) FROM zasp_temporal74.control_intents c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.operation,c.kind)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'cancelSecurityAgentRun','cancel');
       IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test queued cancellation receipt absent';END IF;
      END IF;
      proof_value:=jsonb_build_object('kind','queued');
     ELSE
      IF f.run_id IS NOT NULL THEN
       request_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'step_id',x.step_id,'generation',1,'operation','read','payload','{}'::jsonb);PERFORM zasp_temporal74.effect(request_value);
       IF f.state NOT IN('reserved','started','unknown') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test stopped effect unsupported';END IF;
       IF f.state='reserved' THEN
        IF EXISTS(SELECT 1 FROM zasp_temporal74.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test unsent observation conflict';END IF;
        UPDATE public.zasp_red_team_runs SET state='cancelled',error_code='cancelled',version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,state,attempt)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id,'queued',0) AND worker_id IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL;
        IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test unsent child changed';END IF;
        UPDATE zasp_temporal74.effects SET state='stopped',completed_at=clock_timestamp() WHERE effect_key=f.effect_key;
        UPDATE public.zasp_security_agent_effects SET state='known_failure',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
       END IF;
      END IF;
      proof_value:=jsonb_build_object('kind','admitted','effect_state',COALESCE(f.state,'absent'),'effect_key',f.effect_key);
      UPDATE public.zasp_security_agent_steps SET state=CASE WHEN f.state IN('started','unknown') THEN 'inconclusive' ELSE 'cancelled' END,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
     END IF;
     UPDATE public.zasp_security_agent_runs SET state=CASE WHEN state IN('cancelled','failed','inconclusive','needs_human') THEN state ELSE 'cancelled' END,last_error_code=CASE WHEN f.state IN('started','unknown') THEN 'test_outcome_unknown' ELSE 'test_cancelled_before_dispatch' END,version=version+1,completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
    END IF;
    SELECT proof_value||jsonb_build_object('parent_state',state,'parent_reason',last_error_code) INTO STRICT proof_value FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
    audit_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_single_test_stop',x.run_id);
    INSERT INTO zasp_temporal74.stops VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_version,x.input_digest,q->>'reason',proof_value,audit_value);
    body_value:=jsonb_build_object('reason',q->>'reason','definition_version',x.definition_version,'input_digest',x.input_digest,'proof',proof_value);
    INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(x.organization_id,x.workspace_id,x.environment_id,audit_value,audit_value,x.run_id,session_user,'temporal_test_stopped',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
    IF proof_value->>'kind'='admitted' AND proof_value->>'effect_state'='reserved' THEN
     link_value:=zasp_temporal74.cancelled_link(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
     UPDATE public.zasp_security_agent_test_links SET reconcile_state='settled',reconcile_version=2,reconcile_settlement=link_value,cancellation_outcome='cancelled_before_execution',cancellation_recorded_at=clock_timestamp()
      WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id,reconcile_state,reconcile_version)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id,'pending',1) AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_settlement IS NULL AND cancellation_outcome IS NULL;
     IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test cancellation link changed';END IF;
     UPDATE public.zasp_security_agent_effects SET outcome_id=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_test_outcome',x.run_id||chr(31)||x.step_id),result_digest=digest(decode(link_value->>'proof_hex','hex'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
    END IF;
   END IF;
   evidence_value:=zasp_temporal74.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  END IF;
 END IF;
 RETURN jsonb_build_object('workflow_id',x.workflow_id,'pending',zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id),'evidence',evidence_value);
END $cleanup$;

CREATE FUNCTION zasp_temporal74.test_state(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $state$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;state_value text;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test state authority rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>4096 OR q->'generation' IS DISTINCT FROM '1'::jsonb OR q->>'operation' IS DISTINCT FROM 'read' OR q->'payload' IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test state request rejected';END IF;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test state owner rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test state parent absent';END IF;
 SELECT * INTO f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1);
 state_value:='absent';
 IF f.run_id IS NOT NULL THEN
  PERFORM zasp_temporal74.effect(q);state_value:=f.state;
  IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)) THEN
   PERFORM zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);state_value:='verified';
  ELSIF EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)) THEN
   PERFORM zasp_temporal74.child_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);state_value:='child';
  ELSIF f.state='verified' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test verified proof absent';END IF;
 END IF;
 RETURN jsonb_build_object('run_id',x.run_id,'step_id',x.step_id,'action_key',x.action_key,'test_run_id',x.test_run_id,'effect_key',zasp_temporal74.effect_identity(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1),'state',state_value);
END $state$;

CREATE FUNCTION zasp_temporal74.inspect(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $inspect$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal74.planning_jobs%ROWTYPE;phase text;deadline timestamptz;uncertain boolean;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal74.current_ready() OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test workflow read rejected';END IF;
 x:=zasp_temporal74.start_identity(q);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 SELECT * INTO j FROM zasp_temporal74.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 SELECT deadline_at INTO deadline FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 uncertain:=zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal74.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF j.state='needs_human' THEN
  IF NOT zasp_temporal74.planning_terminal_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test planning terminal proof changed';END IF;
  phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF r.state IN('cancelled','failed','inconclusive','needs_human') OR deadline<=clock_timestamp() THEN phase:='stopping';
 ELSE
  BEGIN
   PERFORM zasp_temporal74.context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   phase:=CASE WHEN j.run_id IS NULL OR j.state<>'admitted' THEN 'planning' WHEN r.state='waiting_approval' THEN 'waiting_approval'
    WHEN EXISTS(SELECT 1 FROM zasp_temporal74.child_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN 'settling' ELSE 'test' END;
  EXCEPTION WHEN SQLSTATE '42501' OR SQLSTATE '40001' THEN phase:='permission_lost';END;
 END IF;
 RETURN jsonb_build_object('phase',phase,'workflow_id',x.workflow_id,'step_id',x.step_id,'action_key',x.action_key,'run_state',r.state,'planning_state',j.state,'deadline',CASE WHEN deadline IS NULL THEN NULL ELSE to_char(deadline AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'unresolved',uncertain);
END $inspect$;
