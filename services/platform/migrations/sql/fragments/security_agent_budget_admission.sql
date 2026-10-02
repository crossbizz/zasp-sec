-- Shared authority for the forthcoming v53 migration. Not a standalone release:
-- release readiness, predecessor restoration and dispatch guards must surround it.
LOCK TABLE public.zasp_security_agent_runs,public.zasp_security_agent_definitions,
 public.zasp_security_agent_definition_versions,public.zasp_security_agent_plans,
 public.zasp_security_agent_effects,public.zasp_security_agent_controls,
 public.zasp_security_agent_steps IN ACCESS EXCLUSIVE MODE NOWAIT;
CREATE TABLE public.zasp_security_agent_org_admissions (
 organization_id text PRIMARY KEY REFERENCES public.zasp_organizations(id)
);
CREATE TABLE public.zasp_security_agent_run_budgets (
 organization_id text NOT NULL,
 workspace_id text NOT NULL,
 environment_id text NOT NULL,
 run_id text NOT NULL,
 definition_id text NOT NULL,
 definition_version bigint NOT NULL,
 started_at timestamptz NOT NULL,
 deadline_at timestamptz CHECK(deadline_at>started_at),
 max_steps integer CHECK(max_steps BETWEEN 1 AND 100),
 max_tokens bigint CHECK(max_tokens BETWEEN 1 AND 12000),
 max_cost_nano_credits bigint CHECK(max_cost_nano_credits BETWEEN 1 AND 1000000000000),
 cost_unit text NOT NULL DEFAULT 'openrouter_credit' CHECK(cost_unit='openrouter_credit'),
 concurrency_limit integer CHECK(concurrency_limit BETWEEN 1 AND 10),
 stop_reason text CHECK(stop_reason IN('budget_deadline_exceeded','budget_steps_exceeded','budget_tokens_exceeded','budget_cost_exceeded','budget_usage_unknown')),
 CHECK(stop_reason IS NOT NULL OR (deadline_at IS NOT NULL AND max_steps IS NOT NULL AND max_tokens IS NOT NULL AND concurrency_limit IS NOT NULL)),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id)
 REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id)
);
-- One planner attempt can acquire at most one outbound reservation. The issuing
-- worker/lease and immutable request identity remain available for settlement
-- after the run lease is gone. NULL usage retains the entire reserved amount;
-- known zero requires a complete response-bound settlement, never defaults.
CREATE TABLE public.zasp_security_agent_provider_reservations (
 organization_id text NOT NULL,
 workspace_id text NOT NULL,
 environment_id text NOT NULL,
 run_id text NOT NULL,
 attempt bigint NOT NULL CHECK(attempt>0),
 reservation_id text NOT NULL CHECK(length(reservation_id) BETWEEN 1 AND 128),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 model text NOT NULL CHECK(length(model) BETWEEN 1 AND 256),
 cost_policy_version text NOT NULL CHECK(length(cost_policy_version) BETWEEN 1 AND 256),
 cost_unit text NOT NULL CHECK(cost_unit='openrouter_credit'),
 maximum_tokens bigint NOT NULL CHECK(maximum_tokens BETWEEN 1 AND 12000),
 maximum_cost_nano_credits bigint NOT NULL CHECK(maximum_cost_nano_credits BETWEEN 1 AND 1000000000000),
 worker_id text NOT NULL CHECK(length(worker_id) BETWEEN 1 AND 128),
 lease_token_digest bytea NOT NULL CHECK(octet_length(lease_token_digest)=32),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 settled_at timestamptz,
 output_digest bytea CHECK(octet_length(output_digest)=32),
 prompt_tokens bigint CHECK(prompt_tokens>=0),
 completion_tokens bigint CHECK(completion_tokens>=0),
 total_tokens bigint CHECK(total_tokens>=0),
 cost_nano_credits bigint CHECK(cost_nano_credits>=0),
 CHECK(
  (settled_at IS NULL AND output_digest IS NULL AND prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL AND cost_nano_credits IS NULL)
  OR
  (settled_at IS NOT NULL AND settled_at>=reserved_at AND output_digest IS NOT NULL AND prompt_tokens IS NOT NULL AND completion_tokens IS NOT NULL AND total_tokens IS NOT NULL AND cost_nano_credits IS NOT NULL
   AND prompt_tokens::numeric+completion_tokens::numeric=total_tokens::numeric)
 ),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,attempt),
 UNIQUE(organization_id,workspace_id,environment_id,run_id,reservation_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id)
  REFERENCES public.zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id)
);
ALTER TABLE public.zasp_security_agent_provider_reservations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_provider_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_provider_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_provider_reservations_authority ON public.zasp_security_agent_provider_reservations
 USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON TABLE public.zasp_security_agent_provider_reservations
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

-- A stable step consumes one slot even across attempts, worker restarts and
-- unknown effects. There is no refund/delete path for started authorization.
CREATE TABLE public.zasp_security_agent_step_reservations (
 organization_id text NOT NULL,
 workspace_id text NOT NULL,
 environment_id text NOT NULL,
 run_id text NOT NULL,
 step_id text NOT NULL,
 action_key text NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id)
  REFERENCES public.zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id)
  REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id)
);
ALTER TABLE public.zasp_security_agent_step_reservations OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_step_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_step_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_step_reservations_authority ON public.zasp_security_agent_step_reservations
 USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON TABLE public.zasp_security_agent_step_reservations
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
ALTER TABLE public.zasp_security_agent_org_admissions OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_org_admissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_org_admissions FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_org_admissions_authority ON public.zasp_security_agent_org_admissions
 USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
ALTER TABLE public.zasp_security_agent_run_budgets OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_run_budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_run_budgets FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_security_agent_run_budgets_authority ON public.zasp_security_agent_run_budgets
 USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON TABLE public.zasp_security_agent_org_admissions,public.zasp_security_agent_run_budgets
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

-- Legacy planner usage was never durably recorded. A known old definition is
-- not proof of unused allowance. Keep known limits and the conservative old
-- start, but stop new work. Unknown limits remain NULL only on stopped rows.
CREATE FUNCTION public.zasp_security_agent_backfill_budget_stops() RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $backfill$
BEGIN
 INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,
  started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit,stop_reason)
 SELECT r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id,r.definition_version,r.created_at,
  CASE WHEN parsed.duration BETWEEN 1 AND 86400 THEN r.created_at+make_interval(secs=>parsed.duration::integer) END,
  CASE WHEN parsed.steps BETWEEN 1 AND 100 THEN parsed.steps::integer END,
  CASE WHEN parsed.tokens BETWEEN 1 AND 12000 THEN parsed.tokens END,
  CASE WHEN parsed.cost BETWEEN 1 AND 1000000000000 THEN parsed.cost END,
  CASE WHEN parsed.concurrency BETWEEN 1 AND 10 THEN parsed.concurrency::integer END,'budget_usage_unknown'
 FROM zasp_security_agent_runs r
 LEFT JOIN zasp_security_agent_definition_versions v
  ON (v.organization_id,v.workspace_id,v.environment_id,v.definition_id,v.version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version)
 LEFT JOIN zasp_security_agent_definitions d
  ON (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(r.organization_id,r.workspace_id,r.environment_id,r.definition_id,r.definition_version)
 CROSS JOIN LATERAL (SELECT coalesce(v.definition,d.body) AS body) source
 CROSS JOIN LATERAL (SELECT
  CASE WHEN source.body->>'max_duration_seconds' ~ '^[0-9]{1,5}$' THEN (source.body->>'max_duration_seconds')::bigint END AS duration,
  CASE WHEN source.body->>'max_steps' ~ '^[0-9]{1,3}$' THEN (source.body->>'max_steps')::bigint END AS steps,
  CASE WHEN source.body->>'ai_token_budget' ~ '^[0-9]{1,5}$' THEN (source.body->>'ai_token_budget')::bigint END AS tokens,
  CASE WHEN source.body->>'max_ai_cost_nano_credits' ~ '^[0-9]{1,13}$' THEN (source.body->>'max_ai_cost_nano_credits')::bigint END AS cost,
  CASE WHEN source.body->>'concurrency_limit' ~ '^[0-9]{1,2}$' THEN (source.body->>'concurrency_limit')::bigint END AS concurrency
 ) parsed
 WHERE r.state IN('queued','planning','waiting_approval','running','verifying','contained')
  AND (r.attempt>0 OR r.state<>'queued'
   OR EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id))
   OR EXISTS(SELECT 1 FROM zasp_security_agent_effects e WHERE (e.organization_id,e.workspace_id,e.environment_id,e.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id))
   OR EXISTS(SELECT 1 FROM zasp_security_agent_controls c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id)));
 UPDATE zasp_security_agent_runs r SET state='needs_human',last_error_code='budget_usage_unknown',
  lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=r.version+1,updated_at=clock_timestamp()
 WHERE r.state IN('queued','planning','waiting_approval','running','verifying')
  AND EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets b
   WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) AND b.stop_reason='budget_usage_unknown');
END
$backfill$;
ALTER FUNCTION public.zasp_security_agent_backfill_budget_stops() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_backfill_budget_stops() FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
SELECT public.zasp_security_agent_backfill_budget_stops();
DROP FUNCTION public.zasp_security_agent_backfill_budget_stops();

CREATE FUNCTION public.zasp_security_agent_claim_budgeted_runs(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer)
 RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE organization_value text;run_row zasp_security_agent_runs%ROWTYPE;
 definition_row zasp_security_agent_definitions%ROWTYPE;budget_row zasp_security_agent_run_budgets%ROWTYPE;
 result_value jsonb:='[]'::jsonb;active_count bigint;active_limit integer;incoming_limit integer;
 start_value timestamptz;now_value timestamptz;duration_value integer;has_budget boolean;
BEGIN
 IF NOT COALESCE(zasp_security_agent_principal_ready('zasp_security_agent_worker'),false)
 OR worker_value IS NULL OR length(worker_value) NOT BETWEEN 1 AND 128
 OR lease_token_value IS NULL OR length(lease_token_value) NOT BETWEEN 16 AND 128
 OR lease_seconds IS NULL OR lease_seconds NOT BETWEEN 30 AND 300
 OR claim_limit IS NULL OR claim_limit NOT BETWEEN 1 AND 25 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent claim rejected';
 END IF;
 -- Oldest eligible organization first; do not wait for another tenant's
 -- admission or work-row locks while holding an organization guard.
 FOR organization_value IN SELECT r.organization_id FROM zasp_security_agent_runs r
  WHERE r.state='queued' AND r.available_at<=clock_timestamp()
   OR r.state IN('planning','running','verifying') AND r.lease_expires_at<=clock_timestamp()
  GROUP BY r.organization_id ORDER BY min(r.available_at),r.organization_id
 LOOP
  -- Serialize first creation too: INSERT ON CONFLICT alone can wait on an
  -- uncommitted insertion even when the subsequent row lock uses SKIP LOCKED.
  CONTINUE WHEN NOT pg_try_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||organization_value,0));
  INSERT INTO zasp_security_agent_org_admissions(organization_id) VALUES(organization_value) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM zasp_security_agent_org_admissions a WHERE a.organization_id=organization_value FOR UPDATE SKIP LOCKED;
  CONTINUE WHEN NOT FOUND;
  now_value:=clock_timestamp();
  -- Lock run then budget before expiry writes. Bulk UPDATE would wait on an
  -- old worker holding a run or settlement row, blocking unrelated tenants.
  FOR run_row IN SELECT r.* FROM zasp_security_agent_runs r
   JOIN zasp_security_agent_run_budgets b USING(organization_id,workspace_id,environment_id,run_id)
   WHERE r.organization_id=organization_value AND (b.stop_reason IS NOT NULL OR b.deadline_at<=now_value)
    AND r.state IN('queued','planning','waiting_approval','running','verifying')
   ORDER BY r.workspace_id,r.environment_id,r.run_id FOR UPDATE OF r SKIP LOCKED
  LOOP
   SELECT * INTO budget_row FROM zasp_security_agent_run_budgets b
    WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id)
    FOR UPDATE SKIP LOCKED;
   CONTINUE WHEN NOT FOUND;
   UPDATE zasp_security_agent_run_budgets SET stop_reason=coalesce(stop_reason,'budget_deadline_exceeded')
    WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);
   UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code=coalesce(budget_row.stop_reason,'budget_deadline_exceeded'),
    lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=now_value
    WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);
  END LOOP;
  FOR run_row IN SELECT r.* FROM zasp_security_agent_runs r WHERE r.organization_id=organization_value
   AND (r.state='queued' AND r.available_at<=clock_timestamp()
    OR r.state IN('planning','running','verifying') AND r.lease_expires_at<=clock_timestamp())
   ORDER BY r.available_at,r.workspace_id,r.environment_id,r.run_id FOR UPDATE SKIP LOCKED
  LOOP
   now_value:=clock_timestamp();
   SELECT * INTO budget_row FROM zasp_security_agent_run_budgets b
    WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id)
    FOR UPDATE SKIP LOCKED;
   has_budget:=FOUND;
   IF NOT has_budget THEN
    -- A locked snapshot is not an absent snapshot and must never be replaced.
    CONTINUE WHEN EXISTS(SELECT 1 FROM zasp_security_agent_run_budgets b
     WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id));
    SELECT * INTO definition_row FROM zasp_security_agent_definitions d
     WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.definition_id,run_row.definition_version)
     AND d.deleted_at IS NULL FOR SHARE SKIP LOCKED;
    IF NOT FOUND THEN
     CONTINUE WHEN EXISTS(SELECT 1 FROM zasp_security_agent_definitions d
      WHERE (d.organization_id,d.workspace_id,d.environment_id,d.definition_id,d.version)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.definition_id,run_row.definition_version) AND d.deleted_at IS NULL);
     UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code='budget_definition_unavailable',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=now_value
      WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);
     CONTINUE;
    END IF;
    incoming_limit:=(definition_row.body->>'concurrency_limit')::integer;
    SELECT count(*),min(b.concurrency_limit) INTO active_count,active_limit
     FROM zasp_security_agent_run_budgets b JOIN zasp_security_agent_runs r
      USING(organization_id,workspace_id,environment_id,run_id)
     WHERE b.organization_id=organization_value AND b.stop_reason IS NULL
      AND r.state IN('queued','planning','waiting_approval','running','verifying','contained');
    CONTINUE WHEN active_count>=least(incoming_limit,coalesce(active_limit,incoming_limit));
    duration_value:=(definition_row.body->>'max_duration_seconds')::integer;
    IF duration_value NOT BETWEEN 1 AND 86400 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='security agent duration rejected';END IF;
    start_value:=CASE WHEN run_row.attempt>0 THEN run_row.created_at ELSE now_value END;
    INSERT INTO zasp_security_agent_run_budgets(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,started_at,deadline_at,max_steps,max_tokens,max_cost_nano_credits,concurrency_limit)
     VALUES(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id,run_row.definition_id,run_row.definition_version,start_value,start_value+make_interval(secs=>duration_value),
      (definition_row.body->>'max_steps')::integer,(definition_row.body->>'ai_token_budget')::bigint,(definition_row.body->>'max_ai_cost_nano_credits')::bigint,incoming_limit)
     RETURNING * INTO budget_row;
   END IF;
   IF budget_row.stop_reason IS NOT NULL OR budget_row.deadline_at<=clock_timestamp() THEN
    UPDATE zasp_security_agent_run_budgets SET stop_reason=coalesce(stop_reason,'budget_deadline_exceeded')
     WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);
    UPDATE zasp_security_agent_runs SET state='needs_human',last_error_code=coalesce(budget_row.stop_reason,'budget_deadline_exceeded'),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp()
     WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);
    CONTINUE;
   END IF;
   UPDATE zasp_security_agent_runs SET state='planning',attempt=attempt+1,lease_owner=worker_value,lease_token=lease_token_value,
    lease_expires_at=clock_timestamp()+make_interval(secs=>lease_seconds),version=version+1,updated_at=clock_timestamp()
    WHERE (organization_id,workspace_id,environment_id,run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id)
    RETURNING * INTO run_row;
   result_value:=result_value||jsonb_build_array(jsonb_build_object('organization_id',run_row.organization_id,'workspace_id',run_row.workspace_id,'environment_id',run_row.environment_id,'run_id',run_row.run_id,'definition_id',run_row.definition_id,'definition_version',run_row.definition_version,'trigger_id',run_row.trigger_id,'state',run_row.state,'version',run_row.version,'attempt',run_row.attempt,'lease_expires_at',to_char(run_row.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'prepared',EXISTS(SELECT 1 FROM zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id))));
   EXIT WHEN jsonb_array_length(result_value)>=claim_limit;
  END LOOP;
  EXIT WHEN jsonb_array_length(result_value)>=claim_limit;
 END LOOP;
 RETURN jsonb_build_object('items',result_value);
END
$claim$;
ALTER FUNCTION public.zasp_security_agent_claim_budgeted_runs(text,text,integer,integer) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_security_agent_claim_budgeted_runs(text,text,integer,integer)
 FROM PUBLIC,zasp_discovery_api,zasp_discovery_worker,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
-- Existing granted claim entry points share authority, including older workers.
CREATE OR REPLACE FUNCTION public.zasp_security_agent_claim_runs_v22(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer)
 RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
 SELECT zasp_security_agent_claim_budgeted_runs(worker_value,lease_token_value,lease_seconds,claim_limit)
$claim$;
CREATE OR REPLACE FUNCTION public.zasp_security_agent_claim_runs(worker_value text,lease_token_value text,lease_seconds integer,claim_limit integer)
 RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
 SELECT zasp_security_agent_claim_budgeted_runs(worker_value,lease_token_value,lease_seconds,claim_limit)
$claim$;
