-- Private classifier leases consume a conservative per-request budget at admission.
-- Each lease is single-use. Configuration changes affect the next admission.
ALTER TABLE public.model_qualifications
 ADD COLUMN IF NOT EXISTS deployment_digest text CHECK(deployment_digest ~ '^sha256:[a-f0-9]{64}$'),
 ADD COLUMN IF NOT EXISTS expires_at timestamptz;

ALTER TABLE public.zasp_action_analysis_evidence ADD COLUMN IF NOT EXISTS intent_deployment_digest text CHECK(intent_deployment_digest ~ '^sha256:[a-f0-9]{64}$');

CREATE TABLE IF NOT EXISTS public.zasp_ai_monthly_usage (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 month_start date NOT NULL, reserved_nano_credits bigint NOT NULL CHECK(reserved_nano_credits>=0),
 PRIMARY KEY(organization_id,workspace_id,environment_id,month_start),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
ALTER TABLE public.zasp_ai_monthly_usage OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_ai_monthly_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_ai_monthly_usage FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.zasp_ai_monthly_usage FROM PUBLIC;
DROP POLICY IF EXISTS usage_owner ON public.zasp_ai_monthly_usage;
CREATE POLICY usage_owner ON public.zasp_ai_monthly_usage TO zasp_discovery_authority USING(true) WITH CHECK(true);

-- The V2 worker may continue polling during an upgrade. Returning no job
-- retires its public OpenRouter path before data can leave the scope.
CREATE OR REPLACE FUNCTION public.zasp_claim_intent_draft() RETURNS jsonb
 LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT 'null'::jsonb $$;

CREATE OR REPLACE FUNCTION public.zasp_claim_qualified_intent(profile text, region text, cost bigint, deployment text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $claim$
DECLARE job record; receipt jsonb; month_key date := date_trunc('month',now() AT TIME ZONE 'UTC')::date;
BEGIN
 IF profile IS NULL OR profile NOT IN ('mistralai/Shieldstral-1.0-3B','nvidia/Nemotron-3.5-Content-Safety') OR region IS NULL OR region NOT IN ('us','eu')
 OR cost IS NULL OR cost NOT BETWEEN 1 AND 1000000000000 OR deployment IS NULL OR deployment !~ '^sha256:[a-f0-9]{64}$' THEN RETURN 'null'::jsonb; END IF;
 SELECT a.seq,a.organization_id,a.workspace_id,a.environment_id,env.monthly_budget_nano_credits AS cap INTO job
 FROM public.zasp_action_analysis_evidence a JOIN public.zasp_action_analysis_versions v USING(organization_id,workspace_id,environment_id,agent_id,revision)
 JOIN public.zasp_environment_ai_controls env USING(organization_id,workspace_id,environment_id)
 JOIN public.zasp_organization_ai_controls org USING(organization_id)
 JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
 LEFT JOIN public.zasp_ai_monthly_usage u ON (u.organization_id,u.workspace_id,u.environment_id,u.month_start)=(a.organization_id,a.workspace_id,a.environment_id,month_key)
 WHERE org.ai_enabled AND org.require_zero_retention AND env.mode IN('zasp_vpc_slm','byoc_self_hosted') AND env.mode=ANY(org.allowed_modes)
 AND (org.allowed_residency IN('us_eu',region||'_only') OR (org.allowed_residency='customer_vpc_only' AND env.mode='byoc_self_hosted')) AND (zasp_authorization80.ai_data_limits(env.organization_id,env.workspace_id,env.environment_id,false)->>'collection_mode') IN('metadata_only','extended')
 AND env.tier2_purpose_drift_enabled AND env.allow_redacted_summaries AND env.tier2_profile=profile
 AND env.monthly_budget_nano_credits-coalesce(u.reserved_nano_credits,0)>=cost
 AND q.purpose='purpose_alignment_check' AND q.provider=env.mode AND q.model=profile AND q.qualified
 AND q.checked_at<=now() AND q.expires_at>now() AND q.deployment_digest=deployment
 AND v.settings->'classifier_opt_in'='true'::jsonb
 AND a.analyzed_at IS NOT NULL AND a.occurred_at>=now()-interval '24 hours' AND a.intent_finished_at IS NULL AND a.intent_attempts<3
 AND (a.intent_ready_at IS NULL OR a.intent_ready_at<=now())
 AND NOT EXISTS (SELECT FROM public.zasp_action_analysis_versions newer WHERE
  (newer.organization_id,newer.workspace_id,newer.environment_id,newer.agent_id)=(a.organization_id,a.workspace_id,a.environment_id,a.agent_id) AND newer.revision>a.revision)
 ORDER BY a.seq LIMIT 1 FOR UPDATE OF a SKIP LOCKED FOR SHARE OF env,org,q;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(job.organization_id,job.workspace_id,job.environment_id,month_key,cost)
 ON CONFLICT (organization_id,workspace_id,environment_id,month_start) DO UPDATE
 SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=job.cap-cost;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 UPDATE public.zasp_action_analysis_evidence SET intent_deployment_digest=deployment,intent_attempts=intent_attempts+1,intent_lease=gen_random_uuid(),intent_ready_at=now()+interval '5 minutes'
 WHERE seq=job.seq RETURNING jsonb_build_object('lease',intent_lease,'features',jsonb_build_object(
 'destination',CASE WHEN destination IN ('internal','approved_partner','external','public') THEN destination ELSE 'unknown' END,
 'has_previous',previous_operation IS NOT NULL,'operation_mismatch','operation_outside_purpose'=ANY(issues),
 'classification_mismatch','classification_outside_purpose'=ANY(issues),'destination_mismatch','destination_outside_purpose'=ANY(issues),
 'sequence_mismatch','sequence_outside_purpose'=ANY(issues))) INTO receipt;
 RETURN receipt;
END $claim$;
ALTER FUNCTION public.zasp_claim_qualified_intent(text,text,bigint,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_claim_qualified_intent(text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_claim_qualified_intent(text,text,bigint,text) TO zasp_discovery_scheduler;
