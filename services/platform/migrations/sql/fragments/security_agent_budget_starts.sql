-- Pending v53 start-boundary guards. Assemble with admission in one migration
-- transaction; this does not yet fence external action-worker application.
CREATE FUNCTION public.zasp_security_agent_budget_can_start(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;budget_row zasp_security_agent_run_budgets%ROWTYPE;reason_value text;
BEGIN
 IF NOT COALESCE(zasp_security_agent_principal_ready('zasp_security_agent_worker')
  AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value)
  AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value)
  AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_token_value) BETWEEN 16 AND 128,false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent budget authority rejected';
 END IF;
 -- Mutation calls concern one tenant. Hold the same organization guard used
 -- by admission before run/budget rows, including when called by old wrappers.
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_value,0));
 INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES(organization_value) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM zasp_security_agent_org_admissions WHERE organization_id=organization_value FOR UPDATE;
 SELECT * INTO run_row FROM zasp_security_agent_runs r
  WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.state,r.lease_owner,r.lease_token)
   =(organization_value,workspace_value,environment_value,run_value,'planning',worker_value,lease_token_value)
   AND r.lease_expires_at>clock_timestamp() FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent lease lost';END IF;
 SELECT * INTO budget_row FROM zasp_security_agent_run_budgets b
  WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE;
 IF NOT FOUND THEN
  INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,stop_reason)
   VALUES(organization_value,workspace_value,environment_value,run_value,run_row.definition_id,run_row.definition_version,run_row.created_at,'budget_usage_unknown')
   RETURNING * INTO budget_row;
 END IF;
 reason_value:=budget_row.stop_reason;
 IF reason_value IS NULL AND budget_row.deadline_at<=clock_timestamp() THEN reason_value:='budget_deadline_exceeded';END IF;
 IF reason_value IS NULL THEN RETURN true;END IF;
 UPDATE zasp_security_agent_run_budgets SET stop_reason=reason_value
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code=reason_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 RETURN false;
END
$guard$;

CREATE FUNCTION public.zasp_security_agent_budget_reserve_step(organization_value text,workspace_value text,environment_value text,run_value text,worker_value text,lease_token_value text,step_value text)
 RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $reserve$
DECLARE step_row zasp_security_agent_steps%ROWTYPE;prior_row zasp_security_agent_step_reservations%ROWTYPE;
 prior_found boolean;step_limit integer;used_steps bigint;
BEGIN
 -- The common guard validates the principal/lease and locks org, run, budget.
 IF NOT zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN RETURN false;END IF;
 SELECT * INTO step_row FROM zasp_security_agent_steps s
  WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.state)
   =(organization_value,workspace_value,environment_value,run_value,step_value,'authorized') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent budget step changed';END IF;
 SELECT * INTO prior_row FROM zasp_security_agent_step_reservations r
  WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.step_id)
   =(organization_value,workspace_value,environment_value,run_value,step_value) FOR UPDATE;
 prior_found:=FOUND;
 -- Recheck after any prerequisite/reservation lock wait. Replay cannot restart
 -- an expired run and cannot rename the action or its authorized input.
 IF NOT zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN RETURN false;END IF;
 IF prior_found THEN
  IF prior_row.action_key IS DISTINCT FROM step_row.action_key OR prior_row.input_digest IS DISTINCT FROM step_row.input_digest THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent budget reservation changed';
  END IF;
  RETURN true;
 END IF;
 SELECT max_steps INTO STRICT step_limit FROM zasp_security_agent_run_budgets
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 SELECT count(*) INTO used_steps FROM zasp_security_agent_step_reservations
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 IF step_limit IS NULL OR used_steps>=step_limit THEN
  UPDATE zasp_security_agent_run_budgets SET stop_reason=CASE WHEN step_limit IS NULL THEN 'budget_usage_unknown' ELSE 'budget_steps_exceeded' END
   WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
  RETURN zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value);
 END IF;
 INSERT INTO zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)
  VALUES(organization_value,workspace_value,environment_value,run_value,step_value,step_row.action_key,step_row.input_digest);
 RETURN true;
END
$reserve$;
ALTER FUNCTION public.zasp_security_agent_budget_reserve_step(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_reserve_step(text,text,text,text,text,text,text)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

CREATE FUNCTION public.zasp_security_agent_budget_stop_result(organization_value text,workspace_value text,environment_value text,run_value text,phase_value text)
 RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $result$
 SELECT jsonb_build_object('run_id',r.run_id,'state',r.state,'version',r.version,'step_id','')
  || CASE phase_value WHEN 'prepare' THEN jsonb_build_object('approval_id','','plan_hash','')
   ELSE jsonb_build_object('effect_state','','outcome_id','','result_digest','') END
 FROM zasp_security_agent_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.state)
  =(organization_value,workspace_value,environment_value,run_value,'needs_human')
$result$;
ALTER FUNCTION public.zasp_security_agent_budget_can_start(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_security_agent_budget_stop_result(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_can_start(text,text,text,text,text,text),public.zasp_security_agent_budget_stop_result(text,text,text,text,text)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

-- Evolve an explicit set of existing entry points, retaining their signatures,
-- owners and ACLs. Missing/unexpected bodies fail the enclosing migration.
-- v53 rollback must restore these predecessor definitions before activation.
DO $install$
DECLARE name_value text;signature_value text;definition_value text;replacement_value text;phase_value text;guard_value text;mutation_value text;target_lock_value text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY[
  'zasp_security_agent_prepare_run','zasp_security_agent_prepare_run_v21','zasp_security_agent_prepare_run_v22',
  'zasp_security_agent_prepare_run_v23','zasp_security_agent_prepare_run_v24','zasp_security_agent_prepare_run_v33',
  'zasp_security_agent_prepare_temporary_policy_run','zasp_security_agent_prepare_temporary_policy_run_v33',
  'zasp_security_agent_prepare_connector_revocation_run','zasp_security_agent_prepare_session_isolation_run',
  'zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21','zasp_security_agent_execute_run_v22',
  'zasp_security_agent_execute_run_v23','zasp_security_agent_execute_run_v24',
  'zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_dispatch_connector_revocation_run',
  'zasp_security_agent_dispatch_session_isolation_run'
 ] LOOP
  phase_value:=CASE WHEN starts_with(name_value,'zasp_security_agent_prepare_') THEN 'prepare' ELSE 'execute' END;
  signature_value:='public.'||name_value||CASE phase_value WHEN 'prepare' THEN '(text,text,text,text,text,text,text,timestamptz,text,text)' ELSE '(text,text,text,text,text,text,text,text)' END;
  SELECT pg_get_functiondef(signature_value::regprocedure) INTO STRICT definition_value;
  IF position(E'\nBEGIN\n' IN definition_value)=0 OR position('zasp_security_agent_budget_can_start' IN definition_value)>0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent budget predecessor rejected';
  END IF;
  guard_value:=' IF NOT public.zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN RETURN public.zasp_security_agent_budget_stop_result(organization_value,workspace_value,environment_value,run_value,'||quote_literal(phase_value)||E');END IF;\n';
  replacement_value:=E'\nBEGIN\n'||guard_value;
  definition_value:=regexp_replace(definition_value,E'\nBEGIN\n',replacement_value);
  -- Entry guards establish org-before-run lock order. Leaf guards recheck the
  -- database clock after predecessor prerequisite locks, before creating work.
  -- Do not silently accept a changed/missing leaf mutation on a future upgrade.
  IF name_value=ANY(ARRAY[
   'zasp_security_agent_prepare_run','zasp_security_agent_prepare_run_v21',
   'zasp_security_agent_prepare_temporary_policy_run','zasp_security_agent_prepare_temporary_policy_run_v33',
   'zasp_security_agent_prepare_connector_revocation_run','zasp_security_agent_prepare_session_isolation_run',
   'zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21',
   'zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_dispatch_connector_revocation_run',
   'zasp_security_agent_dispatch_session_isolation_run'
  ]) THEN
   mutation_value:='  INSERT INTO zasp_security_agent_'||CASE phase_value WHEN 'prepare' THEN 'plans(' ELSE 'effects(' END;
   IF (length(definition_value)-length(replace(definition_value,mutation_value,'')))/length(mutation_value)<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent budget mutation predecessor rejected';
   END IF;
   target_lock_value:='';
   IF name_value=ANY(ARRAY['zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21']) THEN
    -- Finding execution mutates the target in this same transaction. Acquire
    -- its row lock before the final budget check and before creating an effect.
    -- The unchanged UPDATE below still enforces status/version consistency.
    target_lock_value:=E'  PERFORM 1 FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id,finding.status,finding.version)=(organization_value,workspace_value,environment_value,trigger_row.trigger_id,\'open\',trigger_row.trigger_version) FOR UPDATE;\n'
     ||E'  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE=\'40001\',MESSAGE=\'security agent evidence changed\';END IF;\n';
   END IF;
   IF phase_value='execute' THEN
    guard_value:=E' IF NOT public.zasp_security_agent_budget_reserve_step(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value,step_row.step_id) THEN RETURN public.zasp_security_agent_budget_stop_result(organization_value,workspace_value,environment_value,run_value,\'execute\');END IF;\n';
   END IF;
   definition_value:=replace(definition_value,mutation_value,target_lock_value||guard_value||mutation_value);
  END IF;
  EXECUTE definition_value;
 END LOOP;
END
$install$;

-- A stopped preparation is a durable planner result, never an accepted plan.
-- Keep its receipt replayable when the response is lost after committing stop.
ALTER TABLE public.zasp_security_agent_planner_receipts
 DROP CONSTRAINT zasp_security_agent_planner_receipts_outcome_check,
 ADD CONSTRAINT zasp_security_agent_planner_receipts_outcome_check
 CHECK(outcome IN('accepted','planner_unavailable','planner_rejected','budget_stopped'));
DO $planner_stop$
DECLARE name_value text;definition_value text;old_value text;new_value text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY['zasp_security_agent_accept_planner_candidate','zasp_security_agent_accept_planner_candidate_v33'] LOOP
  SELECT pg_get_functiondef(('public.'||name_value||'(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamptz,text,text)')::regprocedure) INTO STRICT definition_value;
  FOR old_value,new_value IN SELECT * FROM (VALUES
   ('prior.outcome<>''accepted''','(prior.outcome NOT IN(''accepted'',''budget_stopped'') OR (prior.outcome=''budget_stopped'' AND (prior.response ? ''budget_stop'' OR prior.response->>''planner_outcome'' IS DISTINCT FROM ''budget_stopped'')))'),
   ('prior.output_digest<>output_digest_value','prior.output_digest IS DISTINCT FROM output_digest_value'),
   ('''planner_outcome'',''accepted''','''planner_outcome'',CASE WHEN result_value->>''state''=''needs_human'' THEN ''budget_stopped'' ELSE ''accepted'' END'),
   ('output_digest_value,''accepted'',model_value','output_digest_value,CASE WHEN result_value->>''state''=''needs_human'' THEN ''budget_stopped'' ELSE ''accepted'' END,model_value')
  ) AS edits(old_text,new_text) LOOP
   IF (length(definition_value)-length(replace(definition_value,old_value,'')))/length(old_value)<>1 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent planner stop predecessor rejected';
   END IF;
   definition_value:=replace(definition_value,old_value,new_value);
  END LOOP;
  EXECUTE definition_value;
 END LOOP;
END
$planner_stop$;

-- Context owns the first planner run-row lock, including calls from accept
-- and fail. Serialize with admission before that lock, not only at prepare.
DO $planner_order$
DECLARE name_value text;definition_value text;anchor_value text;lock_value text;
BEGIN
 anchor_value:='  SELECT * INTO run_row FROM zasp_security_agent_runs run';
 lock_value:=$locks$
  IF NOT COALESCE(zasp_security_agent_principal_ready('zasp_security_agent_worker')
   AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value)
   AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value)
   AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_token_value) BETWEEN 16 AND 128,false) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent planner budget scope rejected';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_value,0));
  INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES(organization_value) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM zasp_security_agent_org_admissions WHERE organization_id=organization_value FOR UPDATE;
$locks$;
 FOREACH name_value IN ARRAY ARRAY['zasp_security_agent_planner_context','zasp_security_agent_planner_context_v33'] LOOP
  SELECT pg_get_functiondef(('public.'||name_value||'(text,text,text,text,text,text)')::regprocedure) INTO STRICT definition_value;
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1
   OR position('security-agent-budget-admission:' IN definition_value)>0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent planner lock predecessor rejected';
  END IF;
  EXECUTE replace(definition_value,anchor_value,lock_value||anchor_value);
 END LOOP;
END
$planner_order$;

CREATE FUNCTION public.zasp_security_agent_budget_context_stop(organization_value text,workspace_value text,environment_value text,run_value text)
 RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $stop$
 SELECT jsonb_build_object('budget_stop',jsonb_build_object('organization_id',r.organization_id,'workspace_id',r.workspace_id,'environment_id',r.environment_id,'run_id',r.run_id,'attempt',r.attempt,'version',r.version,'state',r.state,'reason',b.stop_reason))
 FROM zasp_security_agent_runs r JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.state)=(organization_value,workspace_value,environment_value,run_value,'needs_human') AND b.stop_reason IS NOT NULL
$stop$;
ALTER FUNCTION public.zasp_security_agent_budget_context_stop(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_context_stop(text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

-- Only the registered planner worker may reserve. The caller must establish a
-- verifiable same-model request bound before invoking this function; accepting
-- these declared maxima is not a provider price-policy verifier. No caller is
-- wired until that request boundary and exact settlement are implemented.
CREATE FUNCTION public.zasp_security_agent_budget_reserve_planner(
 organization_value text,workspace_value text,environment_value text,run_value text,
 worker_value text,lease_token_value text,attempt_value bigint,reservation_value text,
 input_digest_value bytea,model_value text,cost_policy_value text,cost_unit_value text,
 maximum_tokens_value bigint,maximum_cost_value bigint)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $planner_reserve$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;budget_row zasp_security_agent_run_budgets%ROWTYPE;
 context_value jsonb;reason_value text;used_tokens numeric;used_cost numeric;
BEGIN
 -- Acquire organization, run, budget in that order and validate the live
 -- principal/lease before inspecting any tenant authority.
 IF NOT zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN
  RETURN zasp_security_agent_budget_context_stop(organization_value,workspace_value,environment_value,run_value);
 END IF;
 SELECT * INTO STRICT run_row FROM zasp_security_agent_runs
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 IF attempt_value IS DISTINCT FROM run_row.attempt OR input_digest_value IS NULL OR octet_length(input_digest_value)<>32
 OR reservation_value IS NULL OR length(reservation_value) NOT BETWEEN 1 AND 128 THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent planner reservation identity changed';
 END IF;
 -- Recompute canonical context, including current definition and prerequisites.
 -- Its final clock guard propagates a committed stop after any prerequisite wait.
 context_value:=zasp_security_agent_planner_context_v33(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value);
 IF context_value ? 'budget_stop' THEN RETURN context_value;END IF;
 IF context_value->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(input_digest_value,'hex') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent planner reservation input changed';
 END IF;
 SELECT * INTO STRICT budget_row FROM zasp_security_agent_run_budgets
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 IF NOT COALESCE(budget_row.max_tokens BETWEEN 1 AND 12000
  AND budget_row.max_cost_nano_credits BETWEEN 1 AND 1000000000000
  AND maximum_tokens_value BETWEEN 1 AND 12000 AND maximum_cost_value BETWEEN 1 AND 1000000000000
  AND length(model_value) BETWEEN 1 AND 256 AND length(cost_policy_value) BETWEEN 1 AND 256
  AND cost_unit_value=budget_row.cost_unit,false) THEN
  reason_value:='budget_usage_unknown';
 ELSIF EXISTS(SELECT 1 FROM zasp_security_agent_provider_reservations p
  WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(organization_value,workspace_value,environment_value,run_value)
   AND (p.settled_at IS NULL OR p.attempt=attempt_value OR p.reservation_id=reservation_value)) THEN
  -- A response lost after commit is not a reusable dispatch permit. Retain all
  -- prior reservations, including unknown outcomes across lease loss/restart.
  reason_value:='budget_usage_unknown';
 ELSE
  SELECT coalesce(sum(CASE WHEN settled_at IS NULL THEN maximum_tokens ELSE total_tokens END),0),
   coalesce(sum(CASE WHEN settled_at IS NULL THEN maximum_cost_nano_credits ELSE cost_nano_credits END),0)
   INTO used_tokens,used_cost FROM zasp_security_agent_provider_reservations
   WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
  IF used_tokens+maximum_tokens_value>budget_row.max_tokens THEN reason_value:='budget_tokens_exceeded';
  ELSIF used_cost+maximum_cost_value>budget_row.max_cost_nano_credits THEN reason_value:='budget_cost_exceeded';END IF;
 END IF;
 IF reason_value IS NOT NULL THEN
  UPDATE zasp_security_agent_run_budgets SET stop_reason=reason_value
   WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
  PERFORM zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value);
  RETURN zasp_security_agent_budget_context_stop(organization_value,workspace_value,environment_value,run_value);
 END IF;
 -- No exception follows a persisted budget stop. Recheck clock/lease just
 -- before creating authority; the caller receives one permit only on commit.
 IF NOT zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN
  RETURN zasp_security_agent_budget_context_stop(organization_value,workspace_value,environment_value,run_value);
 END IF;
 INSERT INTO zasp_security_agent_provider_reservations(organization_id,workspace_id,environment_id,run_id,attempt,reservation_id,input_digest,model,cost_policy_version,cost_unit,maximum_tokens,maximum_cost_nano_credits,worker_id,lease_token_digest)
 VALUES(organization_value,workspace_value,environment_value,run_value,attempt_value,reservation_value,input_digest_value,model_value,cost_policy_value,cost_unit_value,maximum_tokens_value,maximum_cost_value,worker_value,digest(convert_to(lease_token_value,'UTF8'),'sha256'));
 RETURN jsonb_build_object('budget_permit',jsonb_build_object(
  'organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,
  'attempt',attempt_value,'version',run_row.version,'reservation_id',reservation_value,'input_digest','sha256:'||encode(input_digest_value,'hex'),
  'model',model_value,'cost_policy_version',cost_policy_value,'cost_unit',cost_unit_value,
  'maximum_tokens',maximum_tokens_value,'maximum_cost_nano_credits',maximum_cost_value,
  'expires_at',least(run_row.lease_expires_at,budget_row.deadline_at)));
END
$planner_reserve$;
ALTER FUNCTION public.zasp_security_agent_budget_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_budget_reserve_planner(text,text,text,text,text,text,bigint,text,bytea,text,text,text,bigint,bigint) TO zasp_security_agent_worker;

-- Settlement records a past request. It never calls the live-lease start guard
-- or clears a sticky stop; the reservation's original issuer authenticates a
-- late response even when another attempt owns the run now.
CREATE FUNCTION public.zasp_security_agent_budget_settle_planner(
 organization_value text,workspace_value text,environment_value text,run_value text,
 worker_value text,lease_token_value text,attempt_value bigint,reservation_value text,
 output_digest_value bytea,prompt_tokens_value bigint,completion_tokens_value bigint,
 total_tokens_value bigint,cost_value bigint)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $planner_settle$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;budget_row zasp_security_agent_run_budgets%ROWTYPE;
 reservation_row zasp_security_agent_provider_reservations%ROWTYPE;known_value boolean;replay_value boolean:=false;
 reason_value text;used_tokens numeric;used_cost numeric;
BEGIN
 IF NOT COALESCE(zasp_security_agent_principal_ready('zasp_security_agent_worker')
  AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value)
  AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value)
  AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_token_value) BETWEEN 16 AND 128
  AND attempt_value>0 AND length(reservation_value) BETWEEN 1 AND 128,false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent settlement authority rejected';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_value,0));
 PERFORM 1 FROM zasp_security_agent_org_admissions WHERE organization_id=organization_value FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent settlement admission missing';END IF;
 SELECT * INTO run_row FROM zasp_security_agent_runs
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent settlement run missing';END IF;
 SELECT * INTO budget_row FROM zasp_security_agent_run_budgets
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent settlement budget missing';END IF;
 SELECT * INTO reservation_row FROM zasp_security_agent_provider_reservations
  WHERE (organization_id,workspace_id,environment_id,run_id,attempt,reservation_id)
   =(organization_value,workspace_value,environment_value,run_value,attempt_value,reservation_value) FOR UPDATE;
 IF NOT FOUND OR reservation_row.worker_id IS DISTINCT FROM worker_value
  OR reservation_row.lease_token_digest IS DISTINCT FROM digest(convert_to(lease_token_value,'UTF8'),'sha256') THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent settlement issuer changed';
 END IF;
 known_value:=COALESCE(octet_length(output_digest_value)=32 AND prompt_tokens_value>=0 AND completion_tokens_value>=0
  AND total_tokens_value>=0 AND cost_value>=0 AND prompt_tokens_value::numeric+completion_tokens_value::numeric=total_tokens_value::numeric,false);
 IF reservation_row.settled_at IS NOT NULL THEN
  IF NOT known_value OR reservation_row.output_digest IS DISTINCT FROM output_digest_value
   OR reservation_row.prompt_tokens IS DISTINCT FROM prompt_tokens_value OR reservation_row.completion_tokens IS DISTINCT FROM completion_tokens_value
   OR reservation_row.total_tokens IS DISTINCT FROM total_tokens_value OR reservation_row.cost_nano_credits IS DISTINCT FROM cost_value THEN
   RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='security agent settlement replay conflict';
  END IF;
  replay_value:=true;
 ELSIF known_value THEN
  UPDATE zasp_security_agent_provider_reservations SET settled_at=clock_timestamp(),output_digest=output_digest_value,
   prompt_tokens=prompt_tokens_value,completion_tokens=completion_tokens_value,total_tokens=total_tokens_value,cost_nano_credits=cost_value
   WHERE (organization_id,workspace_id,environment_id,run_id,attempt,reservation_id)
    =(organization_value,workspace_value,environment_value,run_value,attempt_value,reservation_value);
 END IF;
 -- Malformed or absent accounting leaves the entire reservation intact. Known
 -- overage is retained too; refusing to store it would undercount real spend.
 reason_value:=budget_row.stop_reason;
 -- Exact replay reports current stop state but performs no accounting or run
 -- mutation. A newer outstanding reservation is not an unknown result of this
 -- old request, and must not be cancelled by its delayed duplicate response.
 IF reason_value IS NULL AND NOT replay_value THEN
  IF NOT known_value OR budget_row.max_tokens IS NULL OR budget_row.max_cost_nano_credits IS NULL THEN
   reason_value:='budget_usage_unknown';
  ELSE
   SELECT coalesce(sum(CASE WHEN settled_at IS NULL THEN maximum_tokens ELSE total_tokens END),0),
    coalesce(sum(CASE WHEN settled_at IS NULL THEN maximum_cost_nano_credits ELSE cost_nano_credits END),0)
    INTO used_tokens,used_cost FROM zasp_security_agent_provider_reservations
    WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
   IF total_tokens_value>reservation_row.maximum_tokens OR used_tokens>budget_row.max_tokens THEN reason_value:='budget_tokens_exceeded';
   ELSIF cost_value>reservation_row.maximum_cost_nano_credits OR used_cost>budget_row.max_cost_nano_credits THEN reason_value:='budget_cost_exceeded';
   ELSIF budget_row.deadline_at<=clock_timestamp() THEN reason_value:='budget_deadline_exceeded';END IF;
  END IF;
 END IF;
 IF reason_value IS NOT NULL AND NOT replay_value THEN
  UPDATE zasp_security_agent_run_budgets SET stop_reason=coalesce(stop_reason,reason_value)
   WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
  UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code=reason_value,
   lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value)
    AND state IN('queued','planning','waiting_approval','running','verifying');
 END IF;
 RETURN jsonb_build_object('budget_settlement',jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,
  'environment_id',environment_value,'run_id',run_value,'attempt',attempt_value,'reservation_id',reservation_value,
  'known',known_value,'stop_reason',coalesce(reason_value,'')));
END
$planner_settle$;
ALTER FUNCTION public.zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION public.zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint) TO zasp_security_agent_worker;

DO $context_stop$
DECLARE suffix_value text;definition_value text;anchor_value text;replacement_value text;
BEGIN
 FOREACH suffix_value IN ARRAY ARRAY['','_v33'] LOOP
  SELECT pg_get_functiondef(('public.zasp_security_agent_planner_context'||suffix_value||'(text,text,text,text,text,text)')::regprocedure) INTO STRICT definition_value;
  anchor_value:='  RETURN jsonb_build_object(''context'',context_value';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget context predecessor rejected';END IF;
  replacement_value:=E'  IF NOT zasp_security_agent_budget_can_start(organization_value,workspace_value,environment_value,run_value,worker_value,lease_token_value) THEN RETURN zasp_security_agent_budget_context_stop(organization_value,workspace_value,environment_value,run_value);END IF;\n';
  EXECUTE replace(definition_value,anchor_value,replacement_value||anchor_value);

  SELECT pg_get_functiondef(('public.zasp_security_agent_accept_planner_candidate'||suffix_value||'(text,text,text,text,text,text,bytea,bytea,text,text,jsonb,text,timestamptz,text,text)')::regprocedure) INTO STRICT definition_value;
  anchor_value:='context_value:=context_envelope->''context'';';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 OR position('  response_value:=result_value||' IN definition_value)=0 THEN RAISE EXCEPTION 'budget accept context predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,'IF context_envelope ? ''budget_stop'' THEN result_value:=zasp_security_agent_budget_stop_result(organization_value,workspace_value,environment_value,run_value,''prepare'');ELSE '||anchor_value);
  definition_value:=replace(definition_value,'  response_value:=result_value||',E'  END IF;\n  response_value:=result_value||');
  EXECUTE definition_value;

  SELECT pg_get_functiondef(('public.zasp_security_agent_fail_planner'||suffix_value||'(text,text,text,text,text,text,bytea,bytea,text,text,text,text,text)')::regprocedure) INTO STRICT definition_value;
  anchor_value:='expected_input:=decode(substring(context_envelope->>''input_digest'' FROM 8),''hex'');';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 OR position('prior.outcome<>error_code_value' IN definition_value)=0 THEN RAISE EXCEPTION 'budget fail context predecessor rejected';END IF;
  definition_value:=replace(definition_value,'prior.outcome<>error_code_value','(prior.outcome NOT IN(error_code_value,''budget_stopped'') OR (prior.outcome=''budget_stopped'' AND NOT (prior.response ? ''budget_stop'')))');
  -- Store a replayable stopped receipt; no exception or failed-run mutation may
  -- follow the nested context stop and roll back or overwrite its authority.
  replacement_value:=$failure$
  IF context_envelope ? 'budget_stop' THEN
   INSERT INTO zasp_security_agent_planner_receipts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,output_digest,outcome,model,policy_version,response)
    VALUES(organization_value,workspace_value,environment_value,run_value,run_row.attempt,input_digest_value,output_digest_value,'budget_stopped',model_value,policy_version_value,context_envelope);
   RETURN context_envelope;
  END IF;
$failure$;
  definition_value:=replace(definition_value,anchor_value,replacement_value||anchor_value);
  -- Tagged stop replay has no extra envelope fields.
  definition_value:=replace(definition_value,'RETURN prior.response||jsonb_build_object(''replayed'',true);','IF prior.outcome=''budget_stopped'' THEN RETURN prior.response;END IF;RETURN prior.response||jsonb_build_object(''replayed'',true);');
  EXECUTE definition_value;
 END LOOP;
END
$context_stop$;

-- Action workers have effect leases, not planner leases. Acquire run/budget
-- before effects without ever waiting on an effect whose owner may need run.
CREATE FUNCTION public.zasp_security_agent_budget_action_gate(organization_value text,workspace_value text,environment_value text,run_value text,step_value text,worker_value text,lease_token_value text,enforce_value boolean)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $action_gate$
DECLARE run_row zasp_security_agent_runs%ROWTYPE;budget_row zasp_security_agent_run_budgets%ROWTYPE;effect_row zasp_security_agent_effects%ROWTYPE;reason_value text;
BEGIN
 IF NOT COALESCE(zasp_security_agent_action_principal_ready() AND zasp_valid_product_id(organization_value) AND zasp_valid_product_id(workspace_value) AND zasp_valid_product_id(environment_value) AND zasp_valid_product_id(run_value) AND zasp_valid_product_id(step_value) AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_token_value) BETWEEN 16 AND 128,false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='security agent action budget authority rejected';
 END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_value,0)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent action budget busy';END IF;
 SELECT * INTO STRICT run_row FROM zasp_security_agent_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE NOWAIT;
 SELECT * INTO budget_row FROM zasp_security_agent_run_budgets b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(organization_value,workspace_value,environment_value,run_value) FOR UPDATE NOWAIT;
 SELECT * INTO effect_row FROM zasp_security_agent_effects e
  WHERE (e.organization_id,e.workspace_id,e.environment_id,e.run_id,e.step_id,e.state,e.lease_owner,e.lease_token)=(organization_value,workspace_value,environment_value,run_value,step_value,'leased',worker_value,lease_token_value)
   AND e.action_key IN('create_temporary_policy','isolate_session') AND e.lease_expires_at>clock_timestamp() FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent action budget lease lost';END IF;
 IF NOT enforce_value THEN RETURN NULL;END IF;
 reason_value:=budget_row.stop_reason;
 IF budget_row.run_id IS NULL THEN
  INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,stop_reason)
   VALUES(organization_value,workspace_value,environment_value,run_value,run_row.definition_id,run_row.definition_version,run_row.created_at,'budget_usage_unknown') RETURNING * INTO budget_row;
  reason_value:='budget_usage_unknown';
 END IF;
 IF reason_value IS NULL AND NOT EXISTS(SELECT 1 FROM zasp_security_agent_step_reservations s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id,s.action_key,s.input_digest)=(organization_value,workspace_value,environment_value,run_value,step_value,effect_row.action_key,effect_row.input_digest)) THEN reason_value:='budget_usage_unknown';END IF;
 IF reason_value IS NULL AND budget_row.deadline_at<=clock_timestamp() THEN reason_value:='budget_deadline_exceeded';END IF;
 IF reason_value IS NULL THEN RETURN NULL;END IF;
 UPDATE zasp_security_agent_run_budgets SET stop_reason=reason_value WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value);
 UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code=reason_value,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
  WHERE (organization_id,workspace_id,environment_id,run_id)=(organization_value,workspace_value,environment_value,run_value) AND state<>'needs_human';
 -- Preserve effect/reservation rows: they can represent partially applied work.
 RETURN jsonb_build_object('organization_id',organization_value,'workspace_id',workspace_value,'environment_id',environment_value,'run_id',run_value,'step_id',step_value,'action_key',effect_row.action_key,'input_digest','sha256:'||encode(effect_row.input_digest,'hex'),'state','needs_human','reason',reason_value);
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent action budget busy';
END
$action_gate$;
ALTER FUNCTION public.zasp_security_agent_budget_action_gate(text,text,text,text,text,text,text,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_action_gate(text,text,text,text,text,text,text,boolean)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

DO $action_source$
DECLARE definition_value text;anchor_value text;replacement_value text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)'::regprocedure) INTO STRICT definition_value;
 anchor_value:='DECLARE target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'action budget declaration predecessor rejected';END IF;
 definition_value:=replace(definition_value,anchor_value,'DECLARE budget_stop_value jsonb;target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;');
 definition_value:=regexp_replace(definition_value,E'\nBEGIN\n',E'\nBEGIN\n IF phase_value=\'apply\' THEN PERFORM zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,false);END IF;\n');
 anchor_value:='  IF target_row.state<>''planned'' THEN';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'action budget source predecessor rejected';END IF;
 replacement_value:=$source_guard$
  IF phase_value='apply' AND (target_row.state='planned' OR target_row.desired_generation IS NULL) THEN
   -- Existing gateway source triggers create these rows. Missing or busy work
   -- is a retry conflict, never permission to enqueue before checking budget.
   BEGIN
    PERFORM 1 FROM zasp_policy_deployment_fairness WHERE organization_id=organization_value FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment authority missing';END IF;
    PERFORM 1 FROM zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(organization_value,workspace_value,environment_value,device_value) FOR UPDATE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment authority missing';END IF;
   EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='policy deployment authority busy';END;
   budget_stop_value:=zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,true);
   IF budget_stop_value IS NOT NULL THEN RETURN jsonb_build_object('budget_action_stop',budget_stop_value||jsonb_build_object('phase',phase_value,'device_id',device_value,'credential_id',credential_value,'sequence',sequence_value,'policy_version',policy_version_value));END IF;
  END IF;
$source_guard$;
 definition_value:=replace(definition_value,anchor_value,replacement_value||anchor_value);
 EXECUTE definition_value;
END
$action_source$;

-- Read-only sticky-stop lookup. Claim already owns effect rows; do not acquire
-- run/budget locks here and invert the apply gate's order.
CREATE FUNCTION public.zasp_security_agent_budget_stopped(organization_value text,workspace_value text,environment_value text,run_value text)
 RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $stopped$
 SELECT EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(organization_value,workspace_value,environment_value,run_value) AND b.stop_reason IS NOT NULL)
$stopped$;
ALTER FUNCTION public.zasp_security_agent_budget_stopped(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_budget_stopped(text,text,text,text) FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

DO $budget_reclaim$
DECLARE name_value text;definition_value text;anchor_value text;replacement_value text;effect_stop text;item_stop text;
BEGIN
 effect_stop:='zasp_security_agent_budget_stopped(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)';
 item_stop:='zasp_security_agent_budget_stopped(item.organization_id,item.workspace_id,item.environment_id,item.run_id)';
 FOREACH name_value IN ARRAY ARRAY['zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_claim_session_policy_effects'] LOOP
  SELECT pg_get_functiondef(to_regprocedure('public.'||name_value||'(text,text,integer,integer)')) INTO STRICT definition_value;
  anchor_value:='SET state=CASE WHEN EXISTS(';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget reclaim predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,'SET state=CASE WHEN '||effect_stop||' OR EXISTS(');
  anchor_value:='effect.state=''leased'' AND effect.lease_expires_at<=transaction_timestamp();';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget pending reclaim predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,'(effect.state=''leased'' AND effect.lease_expires_at<=transaction_timestamp() OR effect.state=''pending'' AND '||effect_stop||');');
  -- A stored source can already be in the deployment queue. For stopped runs
  -- it needs cleanup even if action verification never completed.
  anchor_value:=',''apply'',''verified''))';
  replacement_value:=',''apply'',target.state) AND (target.state=''verified'' OR target.state=''stored'' AND '||effect_stop||'))';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget reclaim target predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,replacement_value);
  anchor_value:=',''apply'',''verified'') AND credential';
  replacement_value:=',''apply'',applied.state) AND (applied.state=''verified'' OR applied.state=''stored'' AND '||effect_stop||') AND credential';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget reclaim active predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,replacement_value);
  anchor_value:=',''apply'',device.id,''verified''))';
  replacement_value:=',''apply'',device.id,applied.state) AND (applied.state=''verified'' OR applied.state=''stored'' AND '||item_stop||'))';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'budget reclaim enumeration predecessor rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,replacement_value);
  EXECUTE definition_value;
 END LOOP;
END
$budget_reclaim$;

-- The renamed pre-deployment leaves remain callable by legacy action roles.
-- Preserve their bundle/replay behavior while applying the same scoped stop.
DO $legacy_action_store$
DECLARE name_value text;definition_value text;anchor_value text;guard_value text;
BEGIN
 FOREACH name_value IN ARRAY ARRAY['zasp_security_agent_store_temporary_policy_target_v27','zasp_security_agent_store_session_policy_target_v27'] LOOP
  SELECT pg_get_functiondef(to_regprocedure('public.'||name_value||'(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamptz,timestamptz,text,bytea,jsonb,bytea,bytea)')) INTO STRICT definition_value;
  anchor_value:='DECLARE target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'legacy action budget declaration rejected';END IF;
  definition_value:=replace(definition_value,anchor_value,'DECLARE budget_stop_value jsonb;target_row zasp_security_agent_temporary_policy_targets%ROWTYPE;');
  definition_value:=regexp_replace(definition_value,E'\nBEGIN\n',E'\nBEGIN\n IF phase_value=\'apply\' THEN PERFORM zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,false);END IF;\n');
  anchor_value:='  IF target_row.state<>''planned'' THEN';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'legacy action budget mutation rejected';END IF;
  guard_value:=$legacy_guard$
  IF phase_value='apply' AND target_row.state='planned' THEN
   -- Protect the bundle FK before the final clock check. Never wait here
   -- while holding run/effect/target authority needed by another worker.
   BEGIN
    PERFORM 1 FROM zasp_gateway_credentials c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.device_id,c.id)=(organization_value,workspace_value,environment_value,device_value,credential_value) FOR KEY SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='legacy policy credential missing';END IF;
   EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='legacy policy credential busy';END;
   budget_stop_value:=zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,true);
   IF budget_stop_value IS NOT NULL THEN RETURN jsonb_build_object('budget_action_stop',budget_stop_value||jsonb_build_object('phase',phase_value,'device_id',device_value,'credential_id',credential_value,'sequence',sequence_value,'policy_version',policy_version_value));END IF;
  END IF;
$legacy_guard$;
  definition_value:=replace(definition_value,anchor_value,guard_value||E'  BEGIN\n'||anchor_value);
  anchor_value:='  RETURN jsonb_build_object(''device_id'',device_value,''phase'',phase_value';
  IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN RAISE EXCEPTION 'legacy action budget return rejected';END IF;
  guard_value:=$legacy_commit_guard$
   -- Unique-index insertion can wait after the precheck. All writes above are
   -- tentative until this current-clock check succeeds. A stop rolls them back
   -- together, then is persisted outside the failed subtransaction.
   IF phase_value='apply' AND target_row.state='planned' THEN
    budget_stop_value:=zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,true);
    IF budget_stop_value IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='ZB001',MESSAGE='legacy policy budget rollback';END IF;
   END IF;
  EXCEPTION WHEN SQLSTATE 'ZB001' THEN
   budget_stop_value:=zasp_security_agent_budget_action_gate(organization_value,workspace_value,environment_value,run_value,step_value,worker_value,lease_token_value,true);
   IF budget_stop_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='legacy policy stop changed';END IF;
   RETURN jsonb_build_object('budget_action_stop',budget_stop_value||jsonb_build_object('phase',phase_value,'device_id',device_value,'credential_id',credential_value,'sequence',sequence_value,'policy_version',policy_version_value));
  END;
$legacy_commit_guard$;
  definition_value:=replace(definition_value,anchor_value,guard_value||anchor_value);
  EXECUTE definition_value;
 END LOOP;
END
$legacy_action_store$;

-- Require explicit cost authority under the existing definition row lock.
-- Validation remains available to legacy drafts; execution activation does not.
-- The predecessor owns receipt replay, CAS, permissions and all mutations.
DO $activation_cost$
DECLARE definition_value text;anchor_value text;guard_value text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text)'::regprocedure) INTO STRICT definition_value;
 anchor_value:='  IF target_activation IN(''supervised'',''autonomous'') THEN';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget activation predecessor rejected';
 END IF;
 guard_value:=$cost_guard$
    IF NOT COALESCE(CASE WHEN jsonb_typeof(definition_row.body->'max_ai_cost_nano_credits')='number'
      AND definition_row.body->>'max_ai_cost_nano_credits' ~ '^[0-9]{1,13}$'
      THEN (definition_row.body->>'max_ai_cost_nano_credits')::bigint BETWEEN 1 AND 1000000000000
      ELSE false END,false) THEN
      RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent cost budget configuration required';
    END IF;
$cost_guard$;
 EXECUTE replace(definition_value,anchor_value,anchor_value||guard_value);
END
$activation_cost$;

-- Activation advances the definition version independently of its workflow
-- mirror. Enforce the public definition CAS, then use the locked mirror's
-- version only for the inherited storage operation. Preserve public intent.
DO $definition_version$
DECLARE definition_value text;anchor_value text;guard_value text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)'::regprocedure) INTO STRICT definition_value;
 anchor_value:='  response_value:=zasp_workflow_mutate_v3(';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget definition version predecessor rejected';
 END IF;
 guard_value:=$version_guard$
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value),0));
  IF mutation_value IN('update','delete') AND NOT EXISTS(
    SELECT 1 FROM zasp_workflow_idempotency WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=
    (organization_value,workspace_value,environment_value,principal_value,operation_value,idempotency_value)) THEN
    -- Workflow updates invoke the definition mirror trigger in this same order.
    PERFORM 1 FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=
      (organization_value,workspace_value,environment_value,'security_agent',definition_value) AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='security agent definition missing';END IF;
    PERFORM 1 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=
      (organization_value,workspace_value,environment_value,definition_value,expected_version_value) AND deleted_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='security agent definition version conflict';END IF;
    SELECT version INTO STRICT expected_version_value FROM zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind,id)=
      (organization_value,workspace_value,environment_value,'security_agent',definition_value);
  END IF;
$version_guard$;
 definition_value:=replace(definition_value,anchor_value,guard_value||anchor_value);
 anchor_value:='  response_value:=response_value||jsonb_build_object(''body'',synchronized.body,''version'',synchronized.version);';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget definition audit predecessor rejected';
 END IF;
 guard_value:=$audit_version$
  UPDATE zasp_workflow_audit SET resource_version=synchronized.version WHERE
    (organization_id,workspace_id,environment_id,audit_id,principal_id,operation,resource_kind,resource_id)=
    (organization_value,workspace_value,environment_value,audit_value,principal_value,operation_value,'security_agent',definition_value);
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent definition audit missing';END IF;
$audit_version$;
 EXECUTE replace(definition_value,anchor_value,guard_value||anchor_value);
END
$definition_version$;

-- Add only the constrained durable stop code to the existing scoped read.
-- Keep its principal check, run visibility, approval projection and ACLs.
DO $public_budget_reason$
DECLARE definition_value text;anchor_value text;projection_value text;
BEGIN
 SELECT pg_get_functiondef('public.zasp_security_agent_run_detail_v24(text,text,text,text)'::regprocedure) INTO STRICT definition_value;
 anchor_value:='SELECT value||jsonb_build_object(''approvals''';
 IF (length(definition_value)-length(replace(definition_value,anchor_value,'')))/length(anchor_value)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='budget public detail predecessor rejected';
 END IF;
 projection_value:=$projection$SELECT value||COALESCE((
  SELECT jsonb_build_object('budget_stop_reason',budget.stop_reason)
  FROM zasp_security_agent_run_budgets budget
  WHERE (budget.organization_id,budget.workspace_id,budget.environment_id,budget.run_id)=
    (organization_value,workspace_value,environment_value,run_value)
    AND budget.stop_reason IS NOT NULL
 ),'{}'::jsonb)||jsonb_build_object('approvals'$projection$;
 EXECUTE replace(definition_value,anchor_value,projection_value);
END
$public_budget_reason$;
