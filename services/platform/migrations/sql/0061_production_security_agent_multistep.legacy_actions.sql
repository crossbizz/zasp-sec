-- Dormant compatibility boundary, not an ordered action adapter. Historical
-- bodies and grants remain saved verbatim for unused release61 demotion.
CREATE FUNCTION zasp_sa_multistep_prior.ordered_action_run(o text,w text,e text,r text) RETURNS boolean
 LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $ordered$
 SELECT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs m WHERE (m.organization_id,m.workspace_id,m.environment_id,m.run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.run_id)=(o,w,e,r) AND p.plan->'contract_version'='61'::jsonb)
$ordered$;

CREATE FUNCTION zasp_sa_multistep_prior.legacy_action_fence(o text,w text,e text,r text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $fence$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='legacy action fence requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 -- Re-read after admission waits. Ordered refusal needs no run/step/effect
 -- locks, so the legacy effect-first and target-first bodies never execute.
 IF zasp_sa_multistep_prior.ordered_action_run(o,w,e,r) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered action requires release61 adapter';END IF;
END $fence$;

DO $legacy_actions$
DECLARE saved record;d text;begin_needle text:=E'\nBEGIN\n';selector text:='WHERE effect.action_key=''create_temporary_policy'' AND';override_count integer:=0;
BEGIN
 FOR saved IN SELECT * FROM zasp_sa_multistep_prior.functions WHERE split_part(signature,'(',1) IN(
  'public.zasp_security_agent_claim_temporary_policy_effects',
  'public.zasp_security_agent_heartbeat_temporary_policy_effect',
  'public.zasp_security_agent_execute_run',
  'public.zasp_security_agent_execute_run_v21',
  'public.zasp_security_agent_execute_run_v22',
  'public.zasp_security_agent_execute_run_v23',
  'public.zasp_security_agent_execute_run_v24',
  'public.zasp_security_agent_finish_temporary_policy_effect',
  'public.zasp_security_agent_store_temporary_policy_target',
  'public.zasp_security_agent_store_temporary_policy_target_v27',
  'public.zasp_policy_deployment_store_temporary_source') ORDER BY signature LOOP
  d:=saved.definition;
  IF (length(d)-length(replace(d,begin_needle,'')))/length(begin_needle)<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy action predecessor shape rejected';END IF;
  IF split_part(saved.signature,'(',1)='public.zasp_security_agent_claim_temporary_policy_effects' THEN
   -- All three selectors must exclude ordered rows before UPDATE or row
   -- locking: expired/stopped recovery, no-target cleanup, and claim. A run
   -- with an existing effect cannot be admitted as ordered work concurrently.
   IF (length(d)-length(replace(d,selector,'')))/length(selector)<>3 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy action claim selectors rejected';END IF;
   d:=replace(d,selector,selector||' NOT zasp_sa_multistep_prior.ordered_action_run(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id) AND');
   d:=replace(d,begin_needle,begin_needle||E'  IF current_setting(''transaction_isolation'')<>''read committed'' THEN RAISE EXCEPTION USING ERRCODE=''25001'',MESSAGE=''legacy action claim requires read committed'';END IF;\n  PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
  ELSE
   -- Every execute entry is fenced before budget53 can lock Organization/run.
   -- The ungranted dispatch leaf is unchanged: no late schema lock beneath a
   -- wrapper that already holds downstream authority. Nested entries reuse
   -- the caller's already-held transaction schema fence.
   d:=replace(d,begin_needle,begin_needle||E'  PERFORM zasp_sa_multistep_prior.legacy_action_fence(organization_value,workspace_value,environment_value,run_value);\n');
  END IF;
  EXECUTE d;
  override_count:=override_count+1;
 END LOOP;
 IF override_count<>11 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='legacy action restoration set incomplete';END IF;
END $legacy_actions$;

ALTER FUNCTION zasp_sa_multistep_prior.ordered_action_run(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_sa_multistep_prior.legacy_action_fence(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.ordered_action_run(text,text,text,text),zasp_sa_multistep_prior.legacy_action_fence(text,text,text,text) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
