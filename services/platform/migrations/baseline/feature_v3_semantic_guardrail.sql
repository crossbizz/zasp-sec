-- Bind a single optional inference and its conservative cost to the original
-- observed. Revoking consent or retiring the qualification fences settlement.
ALTER TABLE public.zasp_guardrail_decisions
 ADD COLUMN IF NOT EXISTS semantic_lease uuid,
 ADD COLUMN IF NOT EXISTS semantic_job text,
 ADD COLUMN IF NOT EXISTS semantic_rule text,
 ADD COLUMN IF NOT EXISTS semantic_profile text,
 ADD COLUMN IF NOT EXISTS semantic_region text,
 ADD COLUMN IF NOT EXISTS semantic_deployment_digest text,
 ADD COLUMN IF NOT EXISTS semantic_state text,
 ADD COLUMN IF NOT EXISTS semantic_deadline timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS zasp_guardrail_semantic_lease ON public.zasp_guardrail_decisions(semantic_lease) WHERE semantic_lease IS NOT NULL;

CREATE OR REPLACE FUNCTION zasp_authorization80.semantic_job_cap(o text,w text,e text,p text,profile text,region text,digest text) RETURNS bigint
LANGUAGE sql VOLATILE SET search_path=pg_catalog,public AS $cap$
 SELECT env.monthly_budget_nano_credits FROM public.zasp_environment_ai_controls env JOIN public.zasp_organization_ai_controls org USING(organization_id)
 JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
 WHERE (env.organization_id,env.workspace_id,env.environment_id)=(o,w,e)
 AND env.mode='zasp_vpc_slm' AND env.mode=ANY(org.allowed_modes) AND org.ai_enabled AND org.require_zero_retention
 AND org.allowed_residency IN('us_eu',region||'_only') AND region IN('us','eu') AND org.allow_private_code_egress AND env.allow_approved_code_snippets
 AND (zasp_authorization80.ai_data_limits(o,w,e,true)->>'collection_mode')='extended'
 AND (p='heuristic_fp_verify' AND env.tier2_heuristic_fp_suppression_enabled OR p='indirect_injection_screen' AND env.tier2_prompt_injection_enabled)
 AND env.tier2_profile=profile AND q.provider=env.mode AND q.model=profile AND q.purpose=p AND q.qualified AND q.expires_at>now() AND q.checked_at<=now()
 AND q.deployment_digest=digest AND digest~'^sha256:[0-9a-f]{64}$' FOR SHARE OF env,org,q
$cap$;

CREATE OR REPLACE FUNCTION zasp_authorization80.semantic_guardrail(o text,w text,e text,a text,id_value text,p text,r text,profile text,region text,cost bigint,digest text,token uuid,outcome text,prob numeric) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $semantic$
DECLARE proof jsonb; observed public.zasp_guardrail_decisions%ROWTYPE; cap bigint; month_key date:=date_trunc('month',now() AT TIME ZONE 'UTC')::date;
 result text; mode text; saved uuid; state jsonb;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,a,'createGuardrailDecision','decide_guardrails','environment',e,false,false,false,true);
 IF proof->>'credential_kind' IS DISTINCT FROM '2' OR NOT coalesce(proof->'pat_ceiling' ? 'decide_guardrails',false) THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 SELECT * INTO observed FROM public.zasp_guardrail_decisions d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.principal_id,d.id)=(o,w,e,a,id_value) FOR UPDATE;
 IF NOT FOUND OR observed.created_at<now()-interval '5 seconds' THEN RETURN 'null'; END IF;
 IF token IS NULL THEN
  IF observed.semantic_state IS NOT NULL OR cost IS NULL OR cost NOT BETWEEN 1 AND 1000000000000 OR outcome IS NOT NULL OR prob IS NOT NULL THEN RETURN 'null'; END IF;
  IF p='heuristic_fp_verify' THEN
   IF r IS NULL OR r NOT IN('injection.instruction_override','injection.role_switch','injection.hidden_text','injection.tool_call') OR jsonb_array_length(observed.rules)<>1 OR observed.rules->0->>'id' IS DISTINCT FROM r THEN RETURN 'null'; END IF;
   SELECT s.mode INTO mode FROM public.rule_suppression_states s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.rule_id)=(o,w,e,r) FOR SHARE;
   IF mode IS NULL OR mode='off' THEN RETURN 'null'; END IF;
  ELSIF p='indirect_injection_screen' THEN
   IF r IS NOT NULL OR observed.decision<>'allow' OR observed.direction<>'input' OR observed.tool_name IS NULL OR observed.rules<>'[]'::jsonb THEN RETURN 'null'; END IF;
  ELSE RETURN 'null'; END IF;
  cap:=zasp_authorization80.semantic_job_cap(o,w,e,p,profile,region,digest);
  IF cap IS NULL OR cap<cost THEN RETURN 'null'; END IF;
  INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(o,w,e,month_key,cost)
  ON CONFLICT(organization_id,workspace_id,environment_id,month_start) DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=cap-cost;
  IF NOT FOUND THEN RETURN 'null'; END IF;
  saved:=gen_random_uuid();
  UPDATE public.zasp_guardrail_decisions SET semantic_lease=saved,semantic_job=p,semantic_rule=r,semantic_profile=profile,semantic_region=region,semantic_deployment_digest=digest,semantic_state='pending',semantic_deadline=clock_timestamp()+interval '2 seconds'
  WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,id_value);
  PERFORM zasp_authorization80.product_settled(proof);
  RETURN jsonb_build_object('lease',saved);
 END IF;
 IF observed.semantic_state IS DISTINCT FROM 'pending' OR observed.semantic_lease IS DISTINCT FROM token THEN RETURN 'null'; END IF;
 result:='coverage_degraded';
 cap:=zasp_authorization80.semantic_job_cap(o,w,e,observed.semantic_job,observed.semantic_profile,observed.semantic_region,observed.semantic_deployment_digest);
 IF observed.semantic_deadline>=clock_timestamp() AND cap>0 AND prob BETWEEN 0 AND 1 THEN
  IF observed.semantic_job='heuristic_fp_verify' AND outcome IN('true_positive','benign_context') THEN
   SELECT s.mode INTO mode FROM public.rule_suppression_states s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.rule_id)=(o,w,e,observed.semantic_rule) FOR SHARE;
   IF mode IN('active','shadow') THEN
    INSERT INTO public.semantic_evaluations VALUES(o,w,e,id_value,observed.semantic_rule,prob,observed.decision='block',observed.semantic_deployment_digest,now());
    state:=zasp_authorization80.suppression_state(o,w,e,observed.semantic_rule);
    result:=CASE WHEN mode='active' AND outcome='benign_context' AND prob<0.5 AND (state->>'eligible')::boolean THEN 'suppressed_benign' WHEN mode='shadow' THEN 'shadow' ELSE 'confirmed' END;
   END IF;
  ELSIF observed.semantic_job='indirect_injection_screen' AND outcome='screened' THEN
   result:=CASE WHEN prob>=0.95 THEN 'detected' ELSE 'screened' END;
  END IF;
 END IF;
 UPDATE public.zasp_guardrail_decisions SET semantic_lease=NULL,semantic_state=result,
 decision=CASE result WHEN 'suppressed_benign' THEN 'allow' WHEN 'detected' THEN 'block' ELSE observed.decision END
 WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,id_value);
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN jsonb_build_object('state',result);
END $semantic$;
ALTER FUNCTION zasp_authorization80.semantic_job_cap(text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.semantic_guardrail(text,text,text,text,text,text,text,text,text,bigint,text,uuid,text,numeric) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.semantic_job_cap(text,text,text,text,text,text,text),zasp_authorization80.semantic_guardrail(text,text,text,text,text,text,text,text,text,bigint,text,uuid,text,numeric) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.semantic_guardrail(text,text,text,text,text,text,text,text,text,bigint,text,uuid,text,numeric) TO zasp_discovery_api;
