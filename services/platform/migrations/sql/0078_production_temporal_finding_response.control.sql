-- Native workflow phase and compensation proof. Cleanup cannot issue an action
-- and remains callable by the registered compensation principal after revocation.
CREATE TABLE zasp_temporal78.stops(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 reason text NOT NULL CHECK(reason IN('workflow_failed','workflow_cancelled','workflow_deadline')),proof jsonb NOT NULL,audit_id text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal78.run_owners);
ALTER TABLE zasp_temporal78.stops OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal78.stops ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal78.stops FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal78.stops USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal78.stops FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal78.stop_evidence(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $evidence$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;t zasp_temporal78.stops%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 SELECT * INTO x FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO t FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(o,w,e,t.audit_id);
 IF t.run_id IS NULL OR x.run_id IS NULL OR rr.completed_at IS NULL OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL
  OR t.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_finding_stop',r)
  OR t.proof IS DISTINCT FROM jsonb_build_object('kind',t.proof->>'kind','run_state',rr.state,'run_reason',rr.last_error_code,'definition_version',x.definition_version,'input_digest',x.input_digest,'plan_hash',encode(rr.plan_hash,'hex'))
  OR (a.run_id,a.event_kind,a.correlation_id,a.body,a.event_digest) IS DISTINCT FROM(r,'temporal_finding_stopped',t.audit_id,jsonb_build_object('reason',t.reason,'proof',t.proof),digest(convert_to(jsonb_build_object('reason',t.reason,'proof',t.proof)::text,'UTF8'),'sha256'))
  OR EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding stop proof changed';END IF;
 IF t.proof->>'kind'='planning' THEN
  IF NOT zasp_temporal78.planning_terminal_valid(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding stopped planner changed';END IF;
 ELSIF t.proof->>'kind'='queued' THEN
  IF rr.state<>'cancelled' OR j.run_id IS NOT NULL OR rr.plan_hash IS NOT NULL OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding queued stop changed';END IF;
 ELSIF t.proof->>'kind'='admitted' THEN
  IF rr.state<>'cancelled' OR j.state IS DISTINCT FROM 'admitted'
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE(organization_id,workspace_id,environment_id,run_id,plan_hash)=(o,w,e,r,rr.plan_hash) AND plan_hash=digest(convert_to(plan::text,'UTF8'),'sha256'))
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE(organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,x.step_id,'cancelled'))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding admitted stop changed';END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding stop kind changed';END IF;
 RETURN jsonb_build_object('kind','stopped','reason',t.reason,'proof',t.proof,'audit_id',t.audit_id);
END $evidence$;

CREATE FUNCTION zasp_temporal78.inspect(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $inspect$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;phase text;deadline timestamptz;uncertain boolean;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding workflow read rejected';END IF;
 x:=zasp_temporal78.start_identity(q);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 SELECT deadline_at INTO deadline FROM public.zasp_security_agent_run_budgets WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 uncertain:=zasp_temporal73.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  PERFORM zasp_temporal78.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF j.state='needs_human' THEN
  IF NOT zasp_temporal78.planning_terminal_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding terminal planner changed';END IF;
  phase:=CASE WHEN uncertain THEN 'pending' ELSE 'terminal' END;
 ELSIF r.state IN('cancelled','failed','inconclusive','needs_human') OR deadline<=clock_timestamp() THEN phase:='stopping';
 ELSE
  BEGIN
   PERFORM zasp_temporal78.context(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   phase:=CASE WHEN j.run_id IS NULL OR j.state<>'admitted' THEN 'planning' WHEN r.state='waiting_approval' THEN 'waiting_approval' ELSE 'apply' END;
  EXCEPTION WHEN SQLSTATE '42501' OR SQLSTATE '40001' THEN phase:='permission_lost';END;
 END IF;
 RETURN jsonb_build_object('phase',phase,'workflow_id',x.workflow_id,'step_id',x.step_id,'action_key',x.action_key,'run_state',r.state,'planning_state',j.state,'deadline',CASE WHEN deadline IS NULL THEN NULL ELSE to_char(deadline AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END,'unresolved',uncertain);
END $inspect$;

CREATE FUNCTION zasp_temporal78.cleanup(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cleanup$
DECLARE x zasp_temporal78.run_owners%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;j zasp_temporal78.planning_jobs%ROWTYPE;proof_value jsonb;evidence_value jsonb;body_value jsonb;audit_value text;kind_value text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='finding cleanup requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding cleanup authority rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','reason']) OR NOT COALESCE(q->>'reason' IN('terminal','workflow_failed','workflow_cancelled','workflow_deadline'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='finding cleanup request rejected';END IF;
 x:=zasp_temporal78.start_identity(q-'reason');
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 IF EXISTS(SELECT 1 FROM zasp_temporal78.response_metadata WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  evidence_value:=zasp_temporal78.effect_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSIF EXISTS(SELECT 1 FROM zasp_temporal78.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN
  evidence_value:=zasp_temporal78.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSE
  SELECT * INTO j FROM zasp_temporal78.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
  IF j.state='needs_human' AND q->>'reason'='terminal' THEN
   IF NOT zasp_temporal78.planning_terminal_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding terminal cleanup proof rejected';END IF;
   evidence_value:=jsonb_build_object('kind','planning_terminal','run_id',x.run_id);
  ELSE
   IF q->>'reason'='terminal' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding terminal cleanup lacks proof';END IF;
   IF EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding partial effect refused';END IF;
   IF j.run_id IS NOT NULL AND j.state<>'admitted' THEN
    PERFORM zasp_temporal78.plan((q-ARRAY['reason','input_digest'])||jsonb_build_object('operation','reconcile','payload','{}'::jsonb));kind_value:='planning';
   ELSE
    kind_value:=CASE WHEN j.run_id IS NULL THEN 'queued' ELSE 'admitted' END;
    IF rr.state NOT IN('queued','waiting_approval','cancelled') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding stop state refused';END IF;
    UPDATE public.zasp_security_agent_steps SET state='cancelled',version=version+1,updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id) AND state IN('authorized','waiting_approval');
    UPDATE public.zasp_security_agent_runs SET state='cancelled',last_error_code='finding_cancelled_before_apply',version=version+1,completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp() WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   END IF;
   SELECT jsonb_build_object('kind',kind_value,'run_state',state,'run_reason',last_error_code,'definition_version',x.definition_version,'input_digest',x.input_digest,'plan_hash',encode(plan_hash,'hex')) INTO STRICT proof_value FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   audit_value:=public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_finding_stop',x.run_id);
   INSERT INTO zasp_temporal78.stops VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,q->>'reason',proof_value,audit_value);
   body_value:=jsonb_build_object('reason',q->>'reason','proof',proof_value);
   INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(x.organization_id,x.workspace_id,x.environment_id,audit_value,audit_value,x.run_id,session_user,'temporal_finding_stopped',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
   evidence_value:=zasp_temporal78.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  END IF;
 END IF;
 RETURN jsonb_build_object('workflow_id',x.workflow_id,'pending',zasp_temporal73.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id),'evidence_digest','sha256:'||encode(digest(convert_to(evidence_value::text,'UTF8'),'sha256'),'hex'));
END $cleanup$;
