DO $guard$
BEGIN
  IF public.zasp_security_agent_live_fingerprint()<>'135723010822313ad7a83c30e7afcec6dd3ef897735a349b0da65d3e23e9298c'
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_execution_state WHERE used_at IS NOT NULL)
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_runs)
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent execution rollback rejected';
  END IF;
END $guard$;

DO $principal_memberships$
DECLARE binding record;
BEGIN
  FOR binding IN SELECT principal_name,authority_role FROM public.zasp_security_agent_principal_bindings LOOP
    EXECUTE format('REVOKE %I FROM %I CASCADE',binding.authority_role,binding.principal_name);
  END LOOP;
END
$principal_memberships$;

DROP FUNCTION public.zasp_security_agent_readiness(text,text);
DROP FUNCTION public.zasp_security_agent_live_fingerprint();
DROP FUNCTION public.zasp_security_agent_claim_runs(text,text,integer,integer);
DROP FUNCTION public.zasp_security_agent_create_run(text,text,text,text,bigint,text,text,bigint,bytea,text,text,text);
DROP FUNCTION public.zasp_security_agent_simulate(text,text,text,text,text,text,bigint,text,text,jsonb,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_activate(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text);
DROP FUNCTION public.zasp_security_agent_set_kill_switch(text,text,text,text,boolean,bigint,text,text,text);
DROP FUNCTION public.zasp_security_agent_definition_detail(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_mutate_definition(text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text);
DROP FUNCTION public.zasp_security_agent_replay_definition(text,text,text,text,text,text,jsonb);
DROP FUNCTION public.zasp_security_agent_definition_value(text,text,text,text);
DROP FUNCTION public.zasp_security_agent_definition_page(text,text,text,text,integer);
DROP FUNCTION public.zasp_security_agent_principals_ready();
DROP FUNCTION public.zasp_security_agent_principal_ready(text);
DROP FUNCTION public.zasp_security_agent_register_principals(text,text,text);
DROP TRIGGER zasp_security_agent_sync_definition_v18 ON public.zasp_workflow_records;
DROP TRIGGER zasp_security_agent_guard_definition_v18 ON public.zasp_workflow_records;
DROP FUNCTION public.zasp_security_agent_sync_definition_trigger();
DROP FUNCTION public.zasp_security_agent_guard_definition_trigger();
DELETE FROM public.zasp_schema_metadata WHERE key='security_agent_execution_fingerprint';
DROP TABLE public.zasp_security_agent_audit;
DROP TABLE public.zasp_security_agent_controls;
DROP TABLE public.zasp_security_agent_effects;
DROP TABLE public.zasp_security_agent_approvals;
DROP TABLE public.zasp_security_agent_steps;
DROP TABLE public.zasp_security_agent_plans;
DROP TABLE public.zasp_security_agent_runs;
DROP TABLE public.zasp_security_agent_trigger_receipts;
DROP TABLE public.zasp_security_agent_kill_switches;
DROP TABLE public.zasp_security_agent_definition_versions;
DROP TABLE public.zasp_security_agent_request_receipts;
DROP TABLE public.zasp_security_agent_definitions;
DROP TABLE public.zasp_security_agent_principal_bindings;
DROP TABLE public.zasp_security_agent_execution_state;

REVOKE zasp_security_agent_api,zasp_security_agent_worker FROM zasp_discovery_authority CASCADE;
DROP ROLE zasp_security_agent_worker;
DROP ROLE zasp_security_agent_api;

DO $schema_marker$
BEGIN
  UPDATE public.zasp_schema_metadata SET value='runtime-data-plane-v1',applied_at=transaction_timestamp() WHERE key='production_core_schema' AND value='security-agent-execution-v1';
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='security agent schema marker drift';END IF;
END
$schema_marker$;
