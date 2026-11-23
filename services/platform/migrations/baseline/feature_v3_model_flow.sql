-- Retain only the latest bounded outcome per model job. Only trusted lease
-- settlement routines can record an observation for a qualified deployment.
CREATE TABLE IF NOT EXISTS public.zasp_private_model_health (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 provider text NOT NULL,model text NOT NULL,purpose text NOT NULL,
 deployment_digest text NOT NULL,observed_at timestamptz NOT NULL,healthy boolean NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,provider,model,purpose),
 FOREIGN KEY(organization_id,workspace_id,environment_id,provider,model,purpose)
 REFERENCES public.model_qualifications(organization_id,workspace_id,environment_id,provider,model,purpose) ON DELETE CASCADE
);
ALTER TABLE public.zasp_private_model_health OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_private_model_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_private_model_health FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_private_model_health FROM PUBLIC;
DROP POLICY IF EXISTS model_health_owner ON public.zasp_private_model_health;
CREATE POLICY model_health_owner ON public.zasp_private_model_health TO zasp_discovery_authority USING(true) WITH CHECK(true);

CREATE OR REPLACE FUNCTION zasp_authorization80.ai_observed_health(o text,w text,e text,service text,pin text,job text,digest text,healthy boolean) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,public AS $observed$
 INSERT INTO public.zasp_private_model_health AS h
 SELECT o,w,e,service,pin,job,digest,clock_timestamp(),healthy
 FROM public.model_qualifications q WHERE (q.organization_id,q.workspace_id,q.environment_id,q.provider,q.model,q.purpose,q.deployment_digest)=(o,w,e,service,pin,job,digest)
 AND q.qualified AND q.checked_at<=now() AND q.expires_at>now()
 ON CONFLICT(organization_id,workspace_id,environment_id,provider,model,purpose) DO UPDATE
 SET observed_at=EXCLUDED.observed_at,deployment_digest=EXCLUDED.deployment_digest,healthy=EXCLUDED.healthy
 WHERE h.observed_at<=EXCLUDED.observed_at
$observed$;
ALTER FUNCTION zasp_authorization80.ai_observed_health(text,text,text,text,text,text,text,boolean) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_observed_health(text,text,text,text,text,text,text,boolean) FROM PUBLIC;

-- A provider appears only when an opted-in job is qualified for this scope.
-- Report observations from the same private deployment, within the last day.
CREATE OR REPLACE FUNCTION zasp_authorization80.ai_model_flow(o text,w text,e text,op text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $flow$
DECLARE env jsonb; org jsonb; mode text; pin text; state text; categories text[]; jobs text[];
BEGIN
 IF op IS NULL OR op NOT IN('getExternalDataFlows','getSystemStatus','listSystemComponents') THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='invalid model health projection'; END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,op,'view','environment',e,false,true,false,false);
 IF NOT EXISTS(SELECT FROM public.zasp_environment_ai_controls c WHERE (c.organization_id,c.workspace_id,c.environment_id)=(o,w,e) AND c.mode<>'deterministic_only') THEN RETURN 'null'; END IF;
 env:=zasp_authorization80.ai_env_snapshot(o,w,e);
 org:=zasp_authorization80.ai_org_snapshot(o);
 mode:=env->>'effective_mode';
 IF mode='deterministic_only' OR (env->>'monthly_budget_nano_credits')::bigint=0 THEN RETURN 'null'; END IF;
 pin:=CASE WHEN mode IN ('zasp_vpc_slm','byoc_self_hosted') THEN env->>'tier2_profile' ELSE env->>'tier3_model_pin' END;
 SELECT array_agg(q.purpose) INTO jobs FROM public.model_qualifications q JOIN (VALUES
  ('purpose_alignment_check','tier2_purpose_drift_enabled'),('indirect_injection_screen','tier2_prompt_injection_enabled'),
  ('heuristic_fp_verify','tier2_heuristic_fp_suppression_enabled'),('agent_discovery_verify','tier3_discovery_purpose_enabled'),
  ('agent_purpose_draft','tier3_discovery_purpose_enabled'),('addon_semantic_audit','tier3_addon_audit_enabled'),
  ('security_agent_triage','tier3_security_agent_planner_enabled'),('security_agent_remediate','tier3_security_agent_planner_enabled')
 ) binding(purpose,capability) ON q.purpose=binding.purpose
 WHERE (q.organization_id,q.workspace_id,q.environment_id,q.provider,q.model)=(o,w,e,mode,pin)
 AND q.qualified AND q.checked_at<=now() AND q.expires_at>now() AND q.deployment_digest IS NOT NULL AND (env->>binding.capability)::boolean;
 IF jobs IS NULL THEN RETURN 'null'; END IF;
 categories:=array_remove(ARRAY[
  CASE WHEN (env->>'allow_redacted_summaries')::boolean THEN 'redacted_summary' END,
  CASE WHEN (org->>'allow_private_code_egress')::boolean AND env->>'collection_mode'='extended' AND (env->>'allow_approved_code_snippets')::boolean THEN 'approved_code_snippet' END,
  CASE WHEN (org->>'allow_private_code_egress')::boolean AND env->>'collection_mode'='extended' AND (env->>'allow_private_addon_bytes')::boolean THEN 'private_addon' END],NULL);
 IF cardinality(categories)=0 THEN RETURN 'null'; END IF;
 SELECT observations.health INTO state FROM (
 SELECT CASE WHEN a.intent_finished_at IS NOT NULL THEN 'healthy' WHEN a.intent_lease IS NULL OR a.intent_ready_at<=now() THEN 'degraded' ELSE 'unknown' END AS health,coalesce(a.intent_finished_at,least(a.intent_ready_at,now())) AS observed_at
 FROM public.zasp_action_analysis_evidence a JOIN public.model_qualifications q USING (organization_id,workspace_id,environment_id)
 WHERE (a.organization_id,a.workspace_id,a.environment_id,q.provider,q.model,q.purpose)=(o,w,e,mode,pin,'purpose_alignment_check')
 AND q.deployment_digest=a.intent_deployment_digest AND q.qualified AND q.expires_at>now()
 AND a.intent_ready_at>now()-interval '1 day' AND q.purpose=ANY(jobs)
 UNION ALL
 SELECT CASE WHEN h.healthy THEN 'healthy' ELSE 'degraded' END,h.observed_at
 FROM public.zasp_private_model_health h JOIN public.model_qualifications q
 USING(organization_id,workspace_id,environment_id,provider,model,purpose,deployment_digest)
 WHERE (h.organization_id,h.workspace_id,h.environment_id,h.provider,h.model)=(o,w,e,mode,pin)
 AND h.purpose=ANY(jobs) AND h.observed_at>now()-interval '1 day'
 ) observations ORDER BY observed_at DESC LIMIT 1;
 RETURN jsonb_build_object('id',mode,'required',false,'enabled',true,'categories',categories,'health',coalesce(state,'unknown'));
END $flow$;
ALTER FUNCTION zasp_authorization80.ai_model_flow(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.ai_model_flow(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.ai_model_flow(text,text,text,text) TO zasp_discovery_api;
