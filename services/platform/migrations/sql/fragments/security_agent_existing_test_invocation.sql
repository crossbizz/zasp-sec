-- Legacy workers have no durable per-category invocation protocol. A linked
-- run may only enter that future versioned protocol, never these old entrypoints.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_legacy_run(o text,w text,e text,r text,authority_value text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $gate$
BEGIN
 IF authority_value NOT IN('zasp_red_team_worker','zasp_red_team_adapter') OR NOT public.zasp_red_team_principal_ready(authority_value) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='red team principal rejected';
 END IF;
 -- Enqueue publishes run and link atomically. Taking the run lock before
 -- observing the link serializes this decision with claim/retry and completion.
 IF authority_value='zasp_red_team_adapter' THEN
  -- The inherited resolver and its safety helpers use transaction-time
  -- authority. Do not introduce a blocking wait before those legacy checks.
  PERFORM 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE NOWAIT;
 ELSE
  PERFORM 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,r)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='linked test invocation protocol required';
 END IF;
END
$gate$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_legacy_run(text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_legacy_run(text,text,text,text,text) FROM PUBLIC;

DO $legacy_invocation$
DECLARE item record;source_value text;guard_value text;anchor_value text:='BEGIN';
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('zasp_red_team_claim_run','text,text,text,text,text,bytea,integer','zasp_red_team_worker'),
  ('zasp_red_team_heartbeat_run','text,text,text,text,text,bytea,integer','zasp_red_team_worker'),
  ('zasp_red_team_cancel_claimed_run','text,text,text,text,text,bytea,bytea','zasp_red_team_worker'),
  ('zasp_red_team_finish_run','text,text,text,text,text,bytea,bytea,text,text,text,text,jsonb,text,text,text,bytea,bigint,jsonb','zasp_red_team_worker'),
  ('zasp_red_team_retry_run','text,text,text,text,text,bytea,bytea,text,timestamp with time zone','zasp_red_team_worker'),
  ('zasp_red_team_resolve_invocation','text,text,text,text,text,text,text,text','zasp_red_team_adapter')
 ) AS functions(name,args,authority) LOOP
  source_value:=pg_get_functiondef(to_regprocedure('public.'||item.name||'('||item.args||')'));
  IF source_value IS NULL OR strpos(source_value,anchor_value)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy invocation predecessor missing';END IF;
  EXECUTE replace(source_value,'FUNCTION public.'||item.name||'(','FUNCTION zasp_existing_tests_predecessor.'||item.name||'(');
  EXECUTE format('ALTER FUNCTION zasp_existing_tests_predecessor.%I(%s) OWNER TO zasp_discovery_authority',item.name,item.args);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_existing_tests_predecessor.%I(%s) FROM PUBLIC',item.name,item.args);
  guard_value:=format(' PERFORM public.zasp_production_security_agent_existing_tests_legacy_run(organization_value,workspace_value,environment_value,run_value,%L);',item.authority);
  source_value:=overlay(source_value placing anchor_value||guard_value from strpos(source_value,anchor_value) for length(anchor_value));
  EXECUTE source_value;
  -- Target resolution now locks the run before deciding which protocol applies.
  EXECUTE format('ALTER FUNCTION public.%I(%s) VOLATILE',item.name,item.args);
 END LOOP;
END
$legacy_invocation$;
