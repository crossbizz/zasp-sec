-- One gate for every worker-callable planner receipt path. It does not create
-- or settle a permit, mutate a stop, or impose provider work on deterministic
-- prepare APIs. Original receipt conflict checks remain in the retained body.
CREATE FUNCTION public.zasp_sa_export_planner_accounting_gate(o text,w text,e text,r text,worker_value text,lease_value text,input_value bytea,output_value bytea,model_value text,failure_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $accounting$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;p public.zasp_security_agent_provider_reservations%ROWTYPE;has_reservation boolean;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_export_guard()
 OR NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(r) AND length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='planner accounting authority unavailable';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 INSERT INTO public.zasp_security_agent_org_admissions(organization_id) VALUES(o) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='planner accounting run missing';END IF;
 -- Receipt presence is not approval: the original body must still compare its
 -- full replay identity, outcome and candidate. No new lease is needed here.
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_planner_receipts WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,rr.attempt)) THEN RETURN;END IF;
 IF (rr.state,rr.lease_owner,rr.lease_token) IS DISTINCT FROM ('planning'::text,worker_value,lease_value) OR rr.lease_expires_at IS NULL OR rr.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='planner accounting lease lost';END IF;
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 -- Delegate stop recording to the existing savepoint/receipt protocol. Raising
 -- after a newly persisted stop here would otherwise undo that durable stop.
 IF NOT FOUND OR b.stop_reason IS NOT NULL OR b.deadline_at<=clock_timestamp() THEN RETURN;END IF;
 SELECT * INTO p FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id,attempt)=(o,w,e,r,rr.attempt) FOR SHARE;
 has_reservation:=FOUND;
 IF rr.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='planner accounting lease expired';END IF;
 IF b.deadline_at<=clock_timestamp() THEN RETURN;END IF;
 IF NOT has_reservation AND failure_value='planner_unavailable' AND output_value IS NULL
 AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL) THEN RETURN;END IF;
 IF NOT has_reservation OR p.settled_at IS NULL OR p.output_digest IS NULL OR p.prompt_tokens IS NULL OR p.completion_tokens IS NULL OR p.total_tokens IS NULL OR p.cost_nano_credits IS NULL
 OR p.input_digest IS DISTINCT FROM input_value OR p.output_digest IS DISTINCT FROM output_value OR p.model IS DISTINCT FROM model_value
 OR p.worker_id IS DISTINCT FROM worker_value OR p.lease_token_digest IS DISTINCT FROM digest(convert_to(lease_value,'UTF8'),'sha256')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND settled_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='planner output accounting incomplete';END IF;
END $accounting$;

-- Install after all family clones exist. Preserve each original implementation
-- and ACL for exact rollback; retained implementations are owner-only.
DO $accounting_wrappers$
DECLARE name_value text;p record;d text;signature_value text;clone_value text;arguments_value text;gate_arguments text;i integer:=0;
BEGIN
 FOREACH name_value IN ARRAY ARRAY[
  'zasp_security_agent_accept_planner_candidate','zasp_security_agent_fail_planner',
  'zasp_security_agent_accept_planner_candidate_v33','zasp_security_agent_fail_planner_v33',
  'zasp_production_security_agent_existing_tests_accept_planner','zasp_production_security_agent_existing_tests_fail_planner',
  'zasp_sa_attack_lab_accept_planner','zasp_sa_attack_lab_fail_planner',
  'zasp_sa_export_accept_core','zasp_sa_export_fail_core'
 ] LOOP
  i:=i+1;
  SELECT oid,proargnames,pg_get_function_arguments(oid) args,pg_get_function_identity_arguments(oid) identity_args INTO STRICT p FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=name_value;
  signature_value:=p.oid::regprocedure::text;
  IF NOT starts_with(name_value,'zasp_sa_export_') THEN PERFORM public.zasp_sa_export_save(signature_value);END IF;
  d:=pg_get_functiondef(p.oid);clone_value:='accounting_'||i::text;
  EXECUTE replace(d,'FUNCTION public.'||name_value||'(','FUNCTION zasp_sa_export_prior.'||clone_value||'(');
  EXECUTE format('ALTER FUNCTION zasp_sa_export_prior.%I(%s) OWNER TO zasp_discovery_authority',clone_value,p.identity_args);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_sa_export_prior.%I(%s) FROM PUBLIC',clone_value,p.identity_args);
  SELECT string_agg(quote_ident(value),',' ORDER BY ordinality) INTO arguments_value FROM unnest(p.proargnames) WITH ORDINALITY x(value,ordinality);
  SELECT string_agg(quote_ident(value),',' ORDER BY ordinality) INTO gate_arguments FROM unnest(p.proargnames) WITH ORDINALITY x(value,ordinality) WHERE ordinality<=9;
  gate_arguments:=gate_arguments||','||CASE WHEN strpos(name_value,'fail_')>0 THEN quote_ident(p.proargnames[11]) ELSE 'NULL::text' END;
  EXECUTE format('CREATE OR REPLACE FUNCTION public.%I(%s) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $body$ BEGIN PERFORM public.zasp_sa_export_planner_accounting_gate(%s); RETURN zasp_sa_export_prior.%I(%s); END $body$',name_value,p.args,gate_arguments,clone_value,arguments_value);
 END LOOP;
END $accounting_wrappers$;
