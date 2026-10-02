-- Dormant ready-step authority. This file consumes application evidence. It
-- never claims actions, creates effects/controls, or replaces legacy adapters.

-- The old decision entry points still have live grants. Fence their original
-- bodies before replay or row locks. Organization admission serializes this
-- read with a concurrently committed ordered plan. The saved definitions and
-- ACLs in promotion are restored byte-for-byte on unused demotion.
CREATE FUNCTION zasp_sa_multistep_prior.legacy_approval_fence(o text,w text,e text,a text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $fence$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='legacy approval fence requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.approval_id)=(o,w,e,a)
  AND (EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs m WHERE (m.organization_id,m.workspace_id,m.environment_id,m.run_id)=(o,w,e,x.run_id))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(o,w,e,x.run_id) AND p.plan->'contract_version'='61'::jsonb))) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered approval requires release61 transition';END IF;
END $fence$;

DO $legacy_decisions$
DECLARE saved record;needle text:=E'BEGIN\n';
BEGIN
 FOR saved IN SELECT * FROM zasp_sa_multistep_prior.functions WHERE signature LIKE 'public.zasp_security_agent_decide_approval%' ORDER BY signature LOOP
  IF (length(saved.definition)-length(replace(saved.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy approval predecessor shape rejected';END IF;
  EXECUTE replace(saved.definition,needle,needle||E'  PERFORM zasp_sa_multistep_prior.legacy_approval_fence(organization_value,workspace_value,environment_value,approval_value);\n');
 END LOOP;
END $legacy_decisions$;

-- Legacy expiry must never lock an ordered approval ahead of its run. Its
-- nonblocking Organization -> budget -> run -> step -> approval order also
-- serializes with legacy decisions through the fence above. Single-step
-- runs without a later budget row retain their original expiry behavior.
CREATE OR REPLACE FUNCTION public.zasp_security_agent_expire_approvals_v28(worker_value text,limit_value integer) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $expire$
DECLARE item record;expired_value integer:=0;approval_version_value bigint;body_value jsonb;audit_value text;correlation_value text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='legacy approval expiry requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_security_agent_principal_ready('zasp_security_agent_worker') OR length(worker_value) NOT BETWEEN 1 AND 128 OR limit_value NOT BETWEEN 1 AND 25 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent approval expiry rejected';END IF;
 FOR item IN
  SELECT approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id,approval.run_id,approval.step_id
  FROM zasp_security_agent_approvals approval JOIN zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id)
  WHERE approval.state='pending' AND approval.expires_at<=clock_timestamp() AND run.state='waiting_approval'
   AND NOT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs m WHERE (m.organization_id,m.workspace_id,m.environment_id,m.run_id)=(approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id))
   AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id) AND p.plan->'contract_version'='61'::jsonb)
  ORDER BY approval.expires_at,approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id LIMIT limit_value
 LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||item.organization_id,0)) THEN CONTINUE;END IF;
  -- Roll back partial row locks on contention. Never hold one Organization's
  -- rows while waiting for another writer or for a different Organization.
  BEGIN
   PERFORM 1 FROM zasp_security_agent_org_admissions WHERE organization_id=item.organization_id FOR UPDATE NOWAIT;
   PERFORM 1 FROM zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id) FOR UPDATE NOWAIT;
   PERFORM 1 FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,'waiting_approval') FOR UPDATE NOWAIT;
   IF NOT FOUND THEN CONTINUE;END IF;
   IF EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id))
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id) AND plan->'contract_version'='61'::jsonb) THEN CONTINUE;END IF;
   PERFORM 1 FROM zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id) FOR UPDATE NOWAIT;
   PERFORM 1 FROM zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(item.organization_id,item.workspace_id,item.environment_id,item.approval_id) FOR UPDATE NOWAIT;
   UPDATE zasp_security_agent_approvals approval SET state='expired',version=approval.version+1,decided_at=clock_timestamp()
    WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.approval_id,approval.run_id,approval.step_id,approval.state)=(item.organization_id,item.workspace_id,item.environment_id,item.approval_id,item.run_id,item.step_id,'pending') AND approval.expires_at<=clock_timestamp() RETURNING approval.version INTO approval_version_value;
   IF NOT FOUND THEN CONTINUE;END IF;
   UPDATE zasp_security_agent_steps step SET state='cancelled',version=step.version+1,updated_at=clock_timestamp()
    WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id,step.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,item.step_id,'waiting_approval');
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval step drift';END IF;
   UPDATE zasp_security_agent_runs run SET state='needs_human',version=run.version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code='approval_expired',updated_at=clock_timestamp(),completed_at=clock_timestamp()
    WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id,run.state)=(item.organization_id,item.workspace_id,item.environment_id,item.run_id,'waiting_approval');
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent approval run drift';END IF;
   body_value:=jsonb_build_object('approval_id',item.approval_id,'run_id',item.run_id,'step_id',item.step_id,'state','expired','version',approval_version_value);
   audit_value:=zasp_discovery_canonical_id(item.organization_id,item.workspace_id,item.environment_id,'security_agent_audit',item.approval_id||chr(31)||'expired');
   correlation_value:=zasp_discovery_canonical_id(item.organization_id,item.workspace_id,item.environment_id,'security_agent_correlation',item.approval_id||chr(31)||'expired');
   INSERT INTO zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,approval_id,actor_id,event_kind,event_digest,body)
    VALUES(item.organization_id,item.workspace_id,item.environment_id,audit_value,correlation_value,item.run_id,item.step_id,item.approval_id,worker_value,'approval_expired',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
   expired_value:=expired_value+1;
  EXCEPTION WHEN lock_not_available THEN CONTINUE;
  END;
 END LOOP;
 RETURN jsonb_build_object('expired',expired_value);
END $expire$;

CREATE FUNCTION zasp_sa_multistep_prior.transition_lock(o text,w text,e text,r text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $lock$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered organization absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered budget absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered run absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 PERFORM 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index FOR UPDATE;
 PERFORM 1 FROM public.zasp_sa_multistep_dependencies WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index FOR SHARE;
 PERFORM 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id,action_key FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY control_id FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id,phase,device_id FOR SHARE;
 -- Gateway revocation/rotation owns source rows before its trigger updates
 -- work. Never wait on either side of that external lock order: retry the
 -- whole transition without writes so the safety writer can always proceed.
 PERFORM 1 FROM public.zasp_policy_deployment_work x WHERE (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e)
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.device_id)=(o,w,e,r,x.device_id)) ORDER BY device_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_gateway_devices x WHERE (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e)
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.device_id)=(o,w,e,r,x.id)) ORDER BY id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_gateway_credentials x WHERE (x.organization_id,x.workspace_id,x.environment_id)=(o,w,e)
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.device_id)=(o,w,e,r,x.device_id)) ORDER BY id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY attempt FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR SHARE;
 PERFORM 1 FROM zasp_sa_multistep_prior.admissions WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
END $lock$;

CREATE FUNCTION zasp_sa_multistep_prior.transition_current(o text,w text,e text,r text,live_value boolean) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;
 b public.zasp_security_agent_run_budgets%ROWTYPE;a zasp_sa_multistep_prior.admissions%ROWTYPE;
 usage public.zasp_security_agent_provider_reservations%ROWTYPE;authority jsonb;
BEGIN
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO a FROM zasp_sa_multistep_prior.admissions WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF a.run_id IS NULL OR p.run_id IS NULL OR rr.run_id IS NULL OR b.run_id IS NULL
  OR p.plan_hash IS DISTINCT FROM rr.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256')
  OR a.response->>'plan_hash' IS DISTINCT FROM 'sha256:'||encode(p.plan_hash,'hex')
  OR (p.definition_id,p.definition_version) IS DISTINCT FROM (rr.definition_id,rr.definition_version)
  OR (b.definition_id,b.definition_version) IS DISTINCT FROM (rr.definition_id,rr.definition_version)
  OR p.plan->'definition_id' IS DISTINCT FROM to_jsonb(p.definition_id) OR p.plan->'definition_version' IS DISTINCT FROM to_jsonb(p.definition_version)
  OR p.plan->'catalog_version' IS DISTINCT FROM to_jsonb(p.catalog_version)
  OR p.plan->'trigger_digest' IS DISTINCT FROM to_jsonb('sha256:'||encode(p.trigger_digest,'hex'))
  OR p.plan->'expires_at' IS DISTINCT FROM to_jsonb(to_char(p.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
  OR p.plan->'contract_version' IS DISTINCT FROM '61'::jsonb OR p.plan->'input_digest' IS DISTINCT FROM a.request->'input_digest'
  OR NOT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs m WHERE (m.organization_id,m.workspace_id,m.environment_id,m.run_id,m.plan_hash,m.definition_id,m.definition_version)=(o,w,e,r,p.plan_hash,rr.definition_id,rr.definition_version))
  OR (SELECT count(*) FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))<>2
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(o,w,e,r)
   AND ((s.step_id,s.action_key,s.authorization_result,s.input_digest) IS DISTINCT FROM (p.plan->'steps'->s.step_index->>'step_id',p.plan->'steps'->s.step_index->>'action',p.plan->'steps'->s.step_index->>'authorization',digest(convert_to((p.plan->'steps'->s.step_index)::text,'UTF8'),'sha256'))
    OR s.authorization_result<>'approval_required' OR s.step_index NOT IN(0,1)))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_dependencies d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.plan_hash,d.step_id,d.predecessor_step_id,d.input_digest,d.predecessor_input_digest,d.required_receipt_kind)=
   (o,w,e,r,p.plan_hash,p.plan->'steps'->1->>'step_id',p.plan->'steps'->0->>'step_id',digest(convert_to((p.plan->'steps'->1)::text,'UTF8'),'sha256'),digest(convert_to((p.plan->'steps'->0)::text,'UTF8'),'sha256'),'temporary_policy_applied.v1'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r)
   AND (x.plan_hash IS DISTINCT FROM p.plan_hash OR x.requester_id IS DISTINCT FROM rr.requested_by OR x.expires_at IS DISTINCT FROM p.expires_at
    OR x.approval_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_approval',r||chr(31)||x.step_id)
    OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id)=(o,w,e,r,x.step_id))))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r)
   AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.action_key,s.input_digest)=(o,w,e,r,x.step_id,x.action_key,x.input_digest))) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered persisted authority changed';END IF;
 SELECT * INTO usage FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,a.attempt);
 IF usage.settled_at IS NULL OR p.plan->>'provider_usage_digest' IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(to_jsonb(usage)::text,'UTF8'),'sha256'),'hex')
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered provider authority changed';END IF;
 IF live_value THEN
  authority:=zasp_sa_multistep_prior.context(o,w,e,r);
  IF p.plan->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(digest(convert_to(authority::text,'UTF8'),'sha256'),'hex')
   OR rr.state NOT IN('waiting_approval','running','verifying') OR rr.completed_at IS NOT NULL
   OR p.expires_at<=clock_timestamp() OR b.deadline_at IS NULL OR b.deadline_at<=clock_timestamp() OR b.stop_reason IS NOT NULL OR b.max_steps IS DISTINCT FROM 2
   OR b.max_tokens IS DISTINCT FROM (authority->'definition'->>'ai_token_budget')::bigint
   OR b.max_cost_nano_credits IS DISTINCT FROM (authority->'definition'->>'max_ai_cost_nano_credits')::bigint
   OR b.concurrency_limit IS DISTINCT FROM (authority->'definition'->>'concurrency_limit')::integer
   OR (SELECT COALESCE(sum(total_tokens),0)>b.max_tokens OR COALESCE(sum(cost_nano_credits),0)>b.max_cost_nano_credits FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
   OR rr.lease_expires_at IS NOT NULL AND rr.lease_expires_at<=clock_timestamp() THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered current authorization unavailable';END IF;
 END IF;
END $current$;

CREATE FUNCTION zasp_sa_multistep_prior.application_ready(o text,w text,e text,r text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $application$
DECLARE receipt public.zasp_sa_multistep_receipts%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 s public.zasp_security_agent_steps%ROWTYPE;c public.zasp_security_agent_controls%ROWTYPE;expected bytea;deployment bytea;expires timestamptz;applied timestamptz;
BEGIN
 SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0);
 SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s.step_id);
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s.step_id,'create_temporary_policy');
 SELECT * INTO c FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id)=(o,w,e,r,s.step_id,receipt.body->>'control_id');
 SELECT digest(s.input_digest||decode(string_agg(encode(envelope_digest,'hex'),'' ORDER BY device_id),'hex'),'sha256'),
  digest(convert_to(jsonb_agg(jsonb_build_array(device_id,credential_id,sequence,policy_version,desired_generation,encode(envelope_digest,'hex')) ORDER BY device_id)::text,'UTF8'),'sha256'),min(expires_at),max(verified_at)
  INTO expected,deployment,expires,applied FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s.step_id,'apply');
 IF s.state<>'succeeded' OR (receipt.action_key,receipt.receipt_kind,receipt.receipt_version,receipt.input_digest,receipt.result_digest) IS DISTINCT FROM ('create_temporary_policy'::text,'temporary_policy_applied.v1'::text,1,s.input_digest,fx.result_digest)
  OR fx.state IS DISTINCT FROM 'cleanup_pending' OR fx.input_digest IS DISTINCT FROM s.input_digest OR expected IS NULL OR expected IS DISTINCT FROM fx.result_digest
  OR receipt.plan_hash IS DISTINCT FROM (SELECT plan_hash FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR receipt.body->>'outcome_id' IS DISTINCT FROM fx.outcome_id
  OR receipt.body->>'deployment_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_deployment',r||chr(31)||s.step_id||chr(31)||encode(deployment,'hex'))
  OR receipt.body->>'applied_at' IS DISTINCT FROM to_char(applied AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  OR receipt.body->>'expires_at' IS DISTINCT FROM to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  OR c.state IS DISTINCT FROM 'active' OR c.action_key IS DISTINCT FROM 'create_temporary_policy' OR c.target_id IS DISTINCT FROM e
  OR receipt.body->'control_version' IS DISTINCT FROM to_jsonb(c.version) OR c.expires_at IS DISTINCT FROM expires OR expires<=clock_timestamp() OR applied>clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.state)=(o,w,e,r,s.step_id,'approved')
   AND a.approver_id IS NOT NULL AND a.approver_id<>a.requester_id AND a.fresh_auth_at IS NOT NULL AND a.decided_at IS NOT NULL
   AND a.fresh_auth_at>=a.decided_at-interval '5 minutes' AND a.fresh_auth_at<=a.decided_at+interval '5 seconds' AND a.expires_at>clock_timestamp())
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,x.input_digest)=(o,w,e,r,s.step_id,s.action_key,s.input_digest))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id)=(o,w,e,r,s.step_id)
   AND (t.phase<>'apply' OR t.state<>'verified' OR t.expires_at<=clock_timestamp() OR t.verified_at IS NULL OR t.desired_generation IS NULL
    OR NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.device_id)=(o,w,e,t.device_id) AND d.applied_generation>=t.desired_generation)
    OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.id,d.state)=(o,w,e,t.device_id,'active'))
    OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.device_id)=(o,w,e,t.device_id) AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1))) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application evidence unavailable';END IF;
 RETURN true;
END $application$;

CREATE FUNCTION zasp_sa_multistep_prior.transition(checksum_value text,fingerprint_value text,request_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $transition$
DECLARE o text;w text;e text;r text;s text;op text;actor text;role_value text;key text;fresh timestamptz;
 rr public.zasp_security_agent_runs%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;step public.zasp_security_agent_steps%ROWTYPE;approval public.zasp_security_agent_approvals%ROWTYPE;
 membership public.zasp_identity_memberships%ROWTYPE;scope_row public.zasp_authorized_scopes%ROWTYPE;
 old_audit public.zasp_security_agent_audit%ROWTYPE;response_value jsonb;approval_value text;event_value text;audit_value text;next_state text;outcome text;
live_value boolean;blocked boolean;execution_stopped boolean;changed boolean:=false;replayed boolean:=false;application boolean:=false;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered transition requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.closed(request_value,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','actor_id','run_version','approval_version','fresh_auth_at']) OR octet_length(request_value::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered transition input rejected';END IF;
 FOREACH key IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(request_value->>key),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered transition identity rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['run_version','approval_version'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'number' OR (request_value->>key)!~'^[1-9][0-9]{0,5}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered transition version rejected';END IF;
 END LOOP;
 o:=request_value->>'organization_id';w:=request_value->>'workspace_id';e:=request_value->>'environment_id';r:=request_value->>'run_id';s:=request_value->>'step_id';op:=request_value->>'operation';actor:=request_value->>'actor_id';
 IF NOT COALESCE(op IN('progress','stop','approve','reject','cancel'),false) OR jsonb_typeof(request_value->'actor_id') IS DISTINCT FROM 'string' OR length(btrim(actor)) NOT BETWEEN 1 AND 128 OR actor~'[[:cntrl:]]'
  OR jsonb_typeof(request_value->'fresh_auth_at') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered transition operation rejected';END IF;
 role_value:=CASE WHEN op IN('progress','stop') THEN 'zasp_security_agent_worker' ELSE 'zasp_security_agent_api' END;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready(role_value),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered transition principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered transition release unavailable';END IF;
 IF op NOT IN('progress','stop') THEN
  IF NOT public.zasp_valid_product_id(actor) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered actor rejected';END IF;
  fresh:=(request_value->>'fresh_auth_at')::timestamptz;
 END IF;
 PERFORM zasp_sa_multistep_prior.transition_lock(o,w,e,r);
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO step FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND OR op IN('progress','stop') AND step.step_index<>1 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered step unavailable';END IF;
 approval_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_approval',r||chr(31)||s);
 event_value:=CASE WHEN op IN('progress','stop') THEN 'ordered_step_ready' WHEN op='cancel' THEN 'ordered_run_cancelled' ELSE 'ordered_approval_decided' END;
 audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s||chr(31)||event_value);
 -- A disabled execution switch revokes new work but must not prevent the
 -- durable conservative transition that makes retained cleanup possible.
 PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test') ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE NOWAIT;
 SELECT count(*)<>4 OR NOT COALESCE(bool_and(execution_enabled),false) INTO execution_stopped FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test');
 blocked:=rr.state NOT IN('waiting_approval','running','verifying') OR rr.completed_at IS NOT NULL
  OR op='stop' AND execution_stopped
  OR b.stop_reason IS NOT NULL OR b.deadline_at IS NULL OR b.deadline_at<=clock_timestamp()
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND expires_at<=clock_timestamp())
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0) AND state IN('failed','inconclusive','cancelled'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('known_failure','unknown_outcome','cleanup_failed','cleaned'));
 -- Only the closed worker stop operation consumes the reader's signal, and
 -- it must establish it again under these locks. Ordinary progress retains
 -- its reviewed current-authority refusal contract.
 IF op='stop' AND NOT blocked THEN blocked:=zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r);END IF;
 IF op='stop' AND NOT blocked THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered stop no longer required';END IF;
 -- A later stop is not a replay of the earlier successor-ready transition.
 -- Keep its immutable evidence under a distinct, deterministic identity.
 IF blocked AND op IN('progress','stop') THEN audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_transition',r||chr(31)||s||chr(31)||event_value||chr(31)||'blocked');END IF;
 SELECT * INTO old_audit FROM public.zasp_security_agent_audit WHERE organization_id=o AND audit_id=audit_value FOR SHARE;
 IF FOUND THEN
  IF NOT(blocked AND op IN('progress','stop')) AND old_audit.body->'request' IS DISTINCT FROM request_value
   OR blocked AND op IN('progress','stop') AND rr.version<>(request_value->>'run_version')::bigint THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered transition replay changed';END IF;
  replayed:=true;
 ELSIF rr.version<>(request_value->>'run_version')::bigint THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered run version changed';END IF;
 IF op='stop' AND (rr.state NOT IN('waiting_approval','running','verifying') OR rr.completed_at IS NOT NULL)
  AND (old_audit.body->'request'->>'operation' IS DISTINCT FROM 'stop' OR old_audit.body->'response'->'run_version' IS DISTINCT FROM to_jsonb(rr.version) OR rr.state<>'needs_human') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered stop terminal replay changed';END IF;
 IF op NOT IN('progress','stop') THEN
  SELECT * INTO membership FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,actor) FOR SHARE;
  scope_row:=zasp_sa_multistep_prior.lock_scope(o,w,e,actor);
  IF membership.active IS DISTINCT FROM true OR NOT COALESCE(public.zasp_effective_scope_permissions(scope_row.permissions,membership.role) ?& ARRAY['view','manage_workflows','run_tests'],false)
   OR fresh IS NULL OR fresh<clock_timestamp()-interval '5 minutes' OR fresh>clock_timestamp()+interval '5 seconds'
   OR op IN('approve','reject') AND actor=rr.requested_by THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered decision authority rejected';END IF;
 END IF;
 IF op IN('approve','reject') AND blocked THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered decision parent stopped';END IF;
 live_value:=NOT blocked AND op<>'cancel';
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,live_value);
 IF op='progress' AND NOT blocked OR op IN('approve','reject') AND step.step_index=1 THEN application:=zasp_sa_multistep_prior.application_ready(o,w,e,r);END IF;
 IF op IN('approve','reject') THEN
  SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  IF approval.approval_id IS NULL OR approval.expires_at<=clock_timestamp() OR step.step_index=1 AND NOT application
   OR NOT replayed AND (step.state<>'waiting_approval' OR approval.state<>'pending' OR approval.version<>(request_value->>'approval_version')::bigint OR approval.approver_id IS NOT NULL OR approval.fresh_auth_at IS NOT NULL OR approval.decided_at IS NOT NULL)
   OR replayed AND (approval.state IS DISTINCT FROM CASE op WHEN 'approve' THEN 'approved' ELSE 'rejected' END OR approval.approver_id IS DISTINCT FROM actor OR approval.fresh_auth_at IS DISTINCT FROM fresh
    OR approval.version<>(request_value->>'approval_version')::bigint+1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered approval is not ready';END IF;
 END IF;
 IF replayed AND NOT blocked THEN
  IF op='progress' AND NOT application
   OR old_audit.body->'response'->'run_version' IS DISTINCT FROM to_jsonb(rr.version) OR old_audit.body->'response'->>'run_state' IS DISTINCT FROM rr.state
   OR old_audit.body->'response'->>'step_state' IS DISTINCT FROM step.state
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.approval_id)=(o,w,e,r,s,approval_value)
    AND to_jsonb(a.version)=old_audit.body->'response'->'approval_version'
    AND (op<>'progress' OR a.state='pending' AND a.approver_id IS NULL AND a.fresh_auth_at IS NULL AND a.decided_at IS NULL)) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered replay state changed';END IF;
  response_value:=old_audit.body->'response';
 ELSIF op='cancel' OR op='reject' OR blocked THEN
  next_state:=CASE WHEN rr.state NOT IN('waiting_approval','running','verifying') OR rr.completed_at IS NOT NULL THEN rr.state WHEN op='cancel' THEN 'cancelled' ELSE 'needs_human' END;
  UPDATE public.zasp_security_agent_steps SET state='cancelled',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('queued','authorized','waiting_approval');
  changed:=FOUND;
  UPDATE public.zasp_security_agent_approvals SET state=CASE WHEN op='reject' AND step_id=s THEN 'rejected' ELSE 'cancelled' END,
   approver_id=CASE WHEN op='reject' AND step_id=s THEN actor ELSE approver_id END,fresh_auth_at=CASE WHEN op='reject' AND step_id=s THEN fresh ELSE fresh_auth_at END,decided_at=clock_timestamp(),version=version+1
   WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,r,'pending');
  changed:=changed OR FOUND OR rr.state<>next_state;
  outcome:='blocked';
 ELSIF op='approve' THEN
  UPDATE public.zasp_security_agent_approvals SET state='approved',approver_id=actor,fresh_auth_at=fresh,decided_at=clock_timestamp(),version=version+1 WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,approval_value);
  UPDATE public.zasp_security_agent_steps SET state='authorized',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  next_state:='running';outcome:='approved';changed:=true;
 ELSIF application THEN
  IF step.state<>'queued' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered successor changed';END IF;
  INSERT INTO public.zasp_security_agent_approvals(organization_id,workspace_id,environment_id,approval_id,run_id,step_id,plan_hash,state,requester_id,expires_at)
   SELECT o,w,e,approval_value,r,s,plan_hash,'pending',rr.requested_by,expires_at FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  UPDATE public.zasp_security_agent_steps SET state='waiting_approval',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  next_state:='waiting_approval';outcome:='ready';changed:=true;
 ELSE outcome:='waiting';next_state:=rr.state;
 END IF;
 IF response_value IS NULL THEN
  IF changed THEN UPDATE public.zasp_security_agent_runs SET state=next_state,version=version+1,updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
   completed_at=CASE WHEN next_state IN('cancelled','needs_human') THEN COALESCE(completed_at,clock_timestamp()) ELSE completed_at END WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);END IF;
  SELECT jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'outcome',outcome,'run_state',x.state,'run_version',x.version,'step_state',y.state,'approval_id',COALESCE(a.approval_id,''),'approval_version',COALESCE(a.version,0)) INTO response_value
   FROM public.zasp_security_agent_runs x JOIN public.zasp_security_agent_steps y USING(organization_id,workspace_id,environment_id,run_id)
   LEFT JOIN public.zasp_security_agent_approvals a ON (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id)=(o,w,e,r,s)
   WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,y.step_id)=(o,w,e,r,s);
  IF changed AND NOT replayed THEN INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
   VALUES(o,w,e,audit_value,audit_value,r,s,actor,event_value,digest(convert_to(request_value::text,'UTF8'),'sha256'),jsonb_build_object('contract_version',61,'request',request_value,'response',response_value));END IF;
 END IF;
 -- Audit/approval writes can wait. Recheck locked authority, clocks, session
 -- role and readiness after those waits; all provisional writes roll back.
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,live_value AND op<>'reject');
 IF application AND NOT blocked AND op<>'cancel' AND NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application changed after wait';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) OR NOT COALESCE(public.zasp_security_agent_principal_ready(role_value),false)
  OR op NOT IN('progress','stop') AND (fresh<clock_timestamp()-interval '5 minutes' OR fresh>clock_timestamp()+interval '5 seconds')
  OR op IN('approve','reject') AND approval.expires_at<=clock_timestamp()
  OR rr.lease_expires_at IS NOT NULL AND live_value AND rr.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered transition expired after wait';END IF;
 RETURN response_value;
END $transition$;

DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname IN('legacy_approval_fence','transition_lock','transition_current','application_ready','transition') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',p);
 END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_sa_multistep_prior TO zasp_security_agent_api;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.transition(text,text,jsonb) TO zasp_security_agent_api,zasp_security_agent_worker;
