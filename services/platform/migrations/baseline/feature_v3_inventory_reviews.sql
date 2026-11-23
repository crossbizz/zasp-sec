-- The lease holds redacted catalog metadata. A retry never spends a second
-- budget reservation or accepts a stale result for a different target.
CREATE TABLE IF NOT EXISTS public.zasp_inventory_semantic_reviews (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor text NOT NULL,
 request_key text NOT NULL,purpose text NOT NULL,target_id text NOT NULL,lease uuid NOT NULL,
 summary jsonb NOT NULL,result jsonb,expires_at timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor,request_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id)
);
ALTER TABLE public.zasp_inventory_semantic_reviews OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_inventory_semantic_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_inventory_semantic_reviews FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_inventory_semantic_reviews FROM PUBLIC;
DO $policy$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_inventory_semantic_reviews' AND policyname='review_authority') THEN
 CREATE POLICY review_authority ON public.zasp_inventory_semantic_reviews TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_review_summary(o text,w text,e text,i text,p text) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public AS $summary$
DECLARE s jsonb; allowed jsonb; refs jsonb;
BEGIN
 IF p='addon_semantic_audit' THEN
  SELECT jsonb_build_object('findings',findings,'ruleset',ruleset,'evidence_refs',coalesce((SELECT jsonb_agg(f->>'rule_id' ORDER BY f->>'rule_id') FROM jsonb_array_elements(findings) f),'[]'::jsonb),'tool_ids','[]'::jsonb)
   INTO s FROM public.zasp_addon_versions WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,i);
  RETURN s;
 END IF;
 SELECT jsonb_build_object('signals',coalesce(a.winning_attributes#>'{discovery,signals}','[]'::jsonb),
  'method',coalesce(a.winning_attributes#>>'{discovery,method}','declared'),'evidence_refs',CASE WHEN a.winning_evidence_id IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(a.winning_evidence_id) END)
  INTO s FROM public.zasp_inventory_entities a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.id,a.product_kind,a.state)=(o,w,e,i,'agent','active');
 IF s IS NULL THEN RETURN NULL; END IF;
 SELECT allowed_tool_ids INTO allowed FROM public.zasp_agent_purpose_versions WHERE (organization_id,workspace_id,environment_id,agent_id)=(o,w,e,i) ORDER BY revision DESC LIMIT 1;
 SELECT coalesce(jsonb_agg(t ORDER BY t),'[]'::jsonb) INTO refs FROM (
  SELECT t FROM jsonb_array_elements_text(coalesce(allowed,'[]'::jsonb)) t
  UNION SELECT a.tool_id FROM public.zasp_agent_suggestions a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.agent_id)=(o,w,e,i)
  ORDER BY 1 LIMIT 64
 ) candidates;
 RETURN s||jsonb_build_object('tool_ids',refs);
END $summary$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_review_allowed(o text,w text,e text,p text,c jsonb) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $allowed$
 SELECT EXISTS(
  SELECT FROM public.zasp_environment_ai_controls v JOIN public.zasp_organization_ai_controls g USING(organization_id)
  JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
  WHERE (v.organization_id,v.workspace_id,v.environment_id)=(o,w,e)
   AND g.ai_enabled AND g.require_zero_retention AND v.mode IN('privatelink_bedrock','privatelink_vertex') AND v.mode=c->>'provider' AND v.tier3_provider=v.mode AND v.mode=ANY(g.allowed_modes)
   AND g.allowed_residency IN ('us_eu',(c->>'region')||'_only') AND v.allow_redacted_summaries AND v.monthly_budget_nano_credits>0
   AND (zasp_authorization80.ai_data_limits(o,w,e,false)->>'collection_mode') IN ('metadata_only','extended')
   AND CASE p WHEN 'addon_semantic_audit' THEN v.tier3_addon_audit_enabled ELSE v.tier3_discovery_purpose_enabled END
   AND v.tier3_model_pin=c->>'model' AND v.credential_digest=c->>'credential_digest' AND v.credential_reference=c->>'credential_reference'
   AND (q.provider,q.model,q.purpose,q.deployment_digest)=(v.mode,v.tier3_model_pin,p,c->>'deployment_digest')
   AND q.qualified AND q.checked_at<=now() AND q.expires_at>now())
$allowed$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_semantic_review(o text,w text,e text,a text,i text,k text,p text,c jsonb,finish jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $review$
DECLARE op text:=CASE p WHEN 'addon_semantic_audit' THEN 'deepScanAddonVersion' WHEN 'agent_discovery_verify' THEN 'verifyAgentDiscovery' WHEN 'agent_purpose_draft' THEN 'draftAgentPurpose' END;
 addon boolean:=p='addon_semantic_audit'; proof jsonb; prior public.zasp_inventory_semantic_reviews%ROWTYPE; evidence jsonb;
 degraded jsonb:=jsonb_build_object('target_id',i,'purpose',p,'coverage_degraded',true,'result',NULL); cost bigint; cap bigint;
 month_key date:=date_trunc('month',now() AT TIME ZONE 'UTC')::date; lease_key uuid:=gen_random_uuid();
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,a,op,'manage_workflows',CASE WHEN addon THEN 'environment' ELSE 'agent' END,CASE WHEN addon THEN e ELSE i END,NOT addon,true,true,true);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM i OR k IS NULL OR k!~'^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='review scope required'; END IF;
 evidence:=zasp_authorization80.inventory_review_summary(o,w,e,i,p);
 IF evidence IS NULL THEN RETURN 'null'::jsonb; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,a,k)::text,5));
 SELECT * INTO prior FROM public.zasp_inventory_semantic_reviews r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.actor,r.request_key)=(o,w,e,a,k);
 IF FOUND AND (prior.purpose,prior.target_id)<>(p,i) THEN RETURN '"conflict"'::jsonb; END IF;
 IF c IS NULL OR c='null'::jsonb OR NOT EXISTS(SELECT FROM public.zasp_environment_ai_controls env WHERE (env.organization_id,env.workspace_id,env.environment_id)=(o,w,e)) THEN RETURN degraded; END IF;
 IF NOT zasp_authorization80.inventory_review_allowed(o,w,e,p,c) THEN RETURN degraded; END IF;
 IF finish IS NOT NULL THEN
  IF prior.lease IS NULL OR prior.lease::text IS DISTINCT FROM finish->>'lease' OR prior.expires_at<=now() OR evidence<>prior.summary THEN RETURN degraded; END IF;
  IF prior.result IS NOT NULL THEN RETURN prior.result; END IF;
  IF finish->'result' IS NOT NULL AND jsonb_typeof(finish->'result')='object' AND octet_length(finish::text)<=32768
   AND zasp_authorization80.inventory_review_result_valid(p,finish->'result',evidence) THEN
    degraded:=degraded||jsonb_build_object('coverage_degraded',false,'result',finish->'result');
  END IF;
  UPDATE public.zasp_inventory_semantic_reviews r SET result=degraded WHERE (r.organization_id,r.workspace_id,r.environment_id,r.actor,r.request_key)=(o,w,e,a,k);
  RETURN degraded;
 END IF;
 IF prior.lease IS NOT NULL THEN RETURN coalesce(prior.result,degraded); END IF;
 cost:=(c->>'cost')::bigint;
 SELECT monthly_budget_nano_credits INTO cap FROM public.zasp_environment_ai_controls WHERE (organization_id,workspace_id,environment_id)=(o,w,e);
 IF cost IS NULL OR cost<1 OR cost>cap OR octet_length(evidence::text)>30000 THEN RETURN degraded; END IF;
 INSERT INTO public.zasp_ai_monthly_usage AS u(organization_id,workspace_id,environment_id,month_start,reserved_nano_credits) VALUES(o,w,e,month_key,cost)
 ON CONFLICT(organization_id,workspace_id,environment_id,month_start) DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=cap-cost;
 IF NOT FOUND THEN RETURN degraded; END IF;
 INSERT INTO public.zasp_inventory_semantic_reviews VALUES(o,w,e,a,k,p,i,lease_key,evidence,NULL,clock_timestamp()+interval '45 seconds');
 PERFORM zasp_authorization80.product_settled(proof); RETURN jsonb_build_object('lease',lease_key,'summary',evidence);
END $review$;

CREATE OR REPLACE FUNCTION zasp_authorization80.inventory_review_result_valid(p text,r jsonb,s jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $valid$
DECLARE fields text[]; refs text;
BEGIN
 IF p='agent_discovery_verify' THEN
  fields:=ARRAY['kind','evidence_refs']; refs:='evidence_refs';
  IF r->>'kind' NOT IN ('autonomous_agent','simple_llm_app','mcp_server','skill_addon','not_an_agent_fp') THEN RETURN false; END IF;
 ELSIF p='agent_purpose_draft' THEN
  fields:=ARRAY['allowed_tool_ids','iam_mismatches']; refs:='iam_mismatches';
  IF jsonb_typeof(r->'allowed_tool_ids') IS DISTINCT FROM 'array' OR NOT ((s->'tool_ids') @> (r->'allowed_tool_ids')) OR jsonb_array_length(r->'allowed_tool_ids')>64 THEN RETURN false; END IF;
 ELSE
  fields:=ARRAY['threat_score','risk_score','tags','citations']; refs:='citations';
  IF jsonb_typeof(r->'threat_score') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'risk_score') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'tags') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
  IF (r->>'threat_score')::numeric NOT BETWEEN 0 AND 1 OR (r->>'risk_score')::numeric NOT BETWEEN 0 AND 1 OR jsonb_array_length(r->'tags')>16 THEN RETURN false; END IF;
 END IF;
 RETURN coalesce(r?&fields AND r-fields='{}'::jsonb AND jsonb_typeof(r->refs)='array' AND jsonb_array_length(r->refs)<=32 AND (s->'evidence_refs') @> (r->refs),false);
END $valid$;
DO $grants$ DECLARE f regprocedure; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.inventory_semantic_review(text,text,text,text,text,text,text,jsonb,jsonb)'::regprocedure,
 'zasp_authorization80.inventory_review_result_valid(text,jsonb,jsonb)'::regprocedure,'zasp_authorization80.inventory_review_summary(text,text,text,text,text)'::regprocedure,
 'zasp_authorization80.inventory_review_allowed(text,text,text,text,jsonb)'::regprocedure] LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f); EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
 IF f::text LIKE '%inventory_semantic_review(%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f); END IF;
 END LOOP;
END $grants$;
