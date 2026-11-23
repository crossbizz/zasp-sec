-- A bounded, metadata-only review of inferred repository candidates. Candidate
-- projection is transactional with the sync. The private inference runs later.
CREATE TABLE IF NOT EXISTS public.zasp_discovery_sync_reviews (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 integration_id text NOT NULL,snapshot_id text NOT NULL,agent_id text NOT NULL,evidence_id text NOT NULL,
 purpose text NOT NULL CHECK (purpose IN ('agent_discovery_verify','agent_purpose_draft')),
 created_at timestamptz NOT NULL DEFAULT now(),lease uuid UNIQUE,expires_at timestamptz,
 summary jsonb,binding jsonb,finished_at timestamptz,result jsonb,
 PRIMARY KEY(organization_id,workspace_id,environment_id,integration_id,snapshot_id,agent_id,purpose),
 FOREIGN KEY(organization_id,workspace_id,environment_id,agent_id) REFERENCES public.zasp_inventory_entities(organization_id,workspace_id,environment_id,id) ON DELETE CASCADE
);
ALTER TABLE public.zasp_discovery_sync_reviews OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_discovery_sync_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_discovery_sync_reviews FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_discovery_sync_reviews FROM PUBLIC;
DO $policy$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_discovery_sync_reviews' AND policyname='review_authority') THEN
 CREATE POLICY review_authority ON public.zasp_discovery_sync_reviews TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy$;
CREATE INDEX IF NOT EXISTS zasp_discovery_sync_reviews_pending ON public.zasp_discovery_sync_reviews(purpose,created_at) WHERE lease IS NULL AND finished_at IS NULL;

CREATE OR REPLACE FUNCTION zasp_authorization80.enqueue_sync_review() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $enqueue$
BEGIN
 IF NEW.product_kind IS DISTINCT FROM 'agent' OR NEW.winning_provider IS DISTINCT FROM 'github' OR NEW.state<>'active'
  OR NEW.winning_evidence_id IS NULL OR NEW.winning_snapshot_id IS NULL OR NEW.winning_integration_id IS NULL
  OR NEW.winning_attributes#>>'{discovery,method}' IS DISTINCT FROM 'inferred'
  OR NEW.winning_attributes#>>'{discovery,platform}' IS DISTINCT FROM 'github_repository'
  OR NOT coalesce(NEW.winning_attributes#>'{discovery,signals}' @> '["layout:tool_schema"]'::jsonb,false)
 THEN RETURN NEW; END IF;
 IF NOT EXISTS (SELECT FROM public.zasp_environment_ai_controls v JOIN public.zasp_organization_ai_controls g USING(organization_id)
  JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
  WHERE (v.organization_id,v.workspace_id,v.environment_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id)
  AND g.ai_enabled AND g.require_zero_retention AND v.mode=ANY(g.allowed_modes) AND v.mode IN ('privatelink_bedrock','privatelink_vertex')
  AND v.tier3_discovery_purpose_enabled AND v.allow_redacted_summaries AND v.monthly_budget_nano_credits>0
  AND q.provider=v.mode AND q.model=v.tier3_model_pin AND q.purpose='agent_discovery_verify' AND q.qualified AND q.checked_at<=now() AND q.expires_at>now()
  AND (zasp_authorization80.ai_data_limits(v.organization_id,v.workspace_id,v.environment_id,false)->>'collection_mode') IN ('metadata_only','extended'))
 THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.winning_integration_id,NEW.winning_snapshot_id)::text,16));
 IF (SELECT count(*) FROM public.zasp_discovery_sync_reviews WHERE
 (organization_id,workspace_id,environment_id,integration_id,snapshot_id,purpose)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.winning_integration_id,NEW.winning_snapshot_id,'agent_discovery_verify'))<8 THEN
  INSERT INTO public.zasp_discovery_sync_reviews(organization_id,workspace_id,environment_id,integration_id,snapshot_id,agent_id,evidence_id,purpose)
   VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.winning_integration_id,NEW.winning_snapshot_id,NEW.id,NEW.winning_evidence_id,'agent_discovery_verify') ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $enqueue$;
ALTER FUNCTION zasp_authorization80.enqueue_sync_review() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.enqueue_sync_review() FROM PUBLIC;
DROP TRIGGER IF EXISTS zasp_queue_sync_review ON public.zasp_inventory_entities;
CREATE TRIGGER zasp_queue_sync_review AFTER INSERT OR UPDATE OF winning_snapshot_id,winning_evidence_id,winning_attributes ON public.zasp_inventory_entities
 FOR EACH ROW EXECUTE FUNCTION zasp_authorization80.enqueue_sync_review();

CREATE OR REPLACE FUNCTION public.zasp_claim_discovery_sync_review(p text,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $claim$
DECLARE job public.zasp_discovery_sync_reviews%ROWTYPE; budget bigint; cost bigint; facts jsonb;
 month_key date:=date_trunc('month',now() AT TIME ZONE 'UTC')::date; lease_id uuid:=gen_random_uuid();
BEGIN
 IF p IS NULL OR p NOT IN ('agent_discovery_verify','agent_purpose_draft') OR (c->>'cost') IS NULL OR (c->>'cost') !~ '^[1-9][0-9]{0,12}$' THEN RETURN 'null'::jsonb; END IF;
 cost:=(c->>'cost')::bigint;
 SELECT j.* INTO job FROM public.zasp_discovery_sync_reviews j
 JOIN public.zasp_inventory_entities a ON (a.organization_id,a.workspace_id,a.environment_id,a.id,a.winning_evidence_id,a.winning_snapshot_id,a.winning_integration_id,a.state,a.product_kind)=(j.organization_id,j.workspace_id,j.environment_id,j.agent_id,j.evidence_id,j.snapshot_id,j.integration_id,'active','agent')
 JOIN public.zasp_environment_ai_controls v ON (v.organization_id,v.workspace_id,v.environment_id)=(j.organization_id,j.workspace_id,j.environment_id)
 LEFT JOIN public.zasp_ai_monthly_usage u ON (u.organization_id,u.workspace_id,u.environment_id,u.month_start)=(j.organization_id,j.workspace_id,j.environment_id,month_key)
 WHERE j.purpose=p AND j.created_at>now()-interval '1 day' AND j.lease IS NULL AND j.finished_at IS NULL
 AND v.monthly_budget_nano_credits-coalesce(u.reserved_nano_credits,0)>=cost
 AND zasp_authorization80.inventory_review_allowed(j.organization_id,j.workspace_id,j.environment_id,p,c)
 ORDER BY j.created_at,j.agent_id LIMIT 1 FOR UPDATE OF j SKIP LOCKED FOR SHARE OF v;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 facts:=zasp_authorization80.inventory_review_summary(job.organization_id,job.workspace_id,job.environment_id,job.agent_id,p);
 IF facts IS NULL OR octet_length(facts::text)>8192 THEN
  UPDATE public.zasp_discovery_sync_reviews SET finished_at=now() WHERE (organization_id,workspace_id,environment_id,integration_id,snapshot_id,agent_id,purpose)=(job.organization_id,job.workspace_id,job.environment_id,job.integration_id,job.snapshot_id,job.agent_id,p);
  RETURN 'null'::jsonb;
 END IF;
 SELECT monthly_budget_nano_credits INTO budget FROM public.zasp_environment_ai_controls WHERE (organization_id,workspace_id,environment_id)=(job.organization_id,job.workspace_id,job.environment_id);
 INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(job.organization_id,job.workspace_id,job.environment_id,month_key,cost)
 ON CONFLICT(organization_id,workspace_id,environment_id,month_start) DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=budget-cost;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 UPDATE public.zasp_discovery_sync_reviews SET lease=lease_id,expires_at=clock_timestamp()+interval '45 seconds',summary=facts,binding=c
 WHERE (organization_id,workspace_id,environment_id,integration_id,snapshot_id,agent_id,purpose)=(job.organization_id,job.workspace_id,job.environment_id,job.integration_id,job.snapshot_id,job.agent_id,p);
 RETURN jsonb_build_object('lease',lease_id,'summary',facts);
END $claim$;
ALTER FUNCTION public.zasp_claim_discovery_sync_review(text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_claim_discovery_sync_review(text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_claim_discovery_sync_review(text,jsonb) TO zasp_discovery_scheduler;

CREATE OR REPLACE FUNCTION public.zasp_finish_discovery_sync_review(l uuid,r jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $finish$
DECLARE j public.zasp_discovery_sync_reviews%ROWTYPE; accepted boolean;
BEGIN
 SELECT * INTO j FROM public.zasp_discovery_sync_reviews WHERE lease=l FOR UPDATE;
 IF NOT FOUND OR j.finished_at IS NOT NULL THEN RETURN false; END IF;
 accepted:=coalesce(j.expires_at>clock_timestamp() AND jsonb_typeof(r)='object' AND octet_length(r::text)<=16384
  AND zasp_authorization80.inventory_review_allowed(j.organization_id,j.workspace_id,j.environment_id,j.purpose,j.binding)
  AND EXISTS(SELECT FROM public.zasp_inventory_entities a WHERE
   (a.organization_id,a.workspace_id,a.environment_id,a.id,a.winning_snapshot_id,a.winning_evidence_id,a.winning_integration_id,a.state)=(j.organization_id,j.workspace_id,j.environment_id,j.agent_id,j.snapshot_id,j.evidence_id,j.integration_id,'active'))
  AND j.summary=zasp_authorization80.inventory_review_summary(j.organization_id,j.workspace_id,j.environment_id,j.agent_id,j.purpose)
  AND zasp_authorization80.inventory_review_result_valid(j.purpose,r,j.summary)
  AND (j.purpose<>'agent_discovery_verify' OR jsonb_array_length(r->'evidence_refs')>0),false);
 UPDATE public.zasp_discovery_sync_reviews SET finished_at=now(),result=CASE WHEN accepted THEN r END WHERE lease=l;
 IF accepted AND j.purpose='agent_discovery_verify' AND r->>'kind'='autonomous_agent' THEN
  INSERT INTO public.zasp_discovery_sync_reviews(organization_id,workspace_id,environment_id,integration_id,snapshot_id,agent_id,evidence_id,purpose)
  VALUES(j.organization_id,j.workspace_id,j.environment_id,j.integration_id,j.snapshot_id,j.agent_id,j.evidence_id,'agent_purpose_draft') ON CONFLICT DO NOTHING;
 END IF;
 RETURN accepted;
END $finish$;
ALTER FUNCTION public.zasp_finish_discovery_sync_review(uuid,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_finish_discovery_sync_review(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_finish_discovery_sync_review(uuid,jsonb) TO zasp_discovery_scheduler;

CREATE OR REPLACE FUNCTION zasp_authorization80.agent_posture_with_sync(o text,w text,e text,i text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $posture$
DECLARE base jsonb; reviews jsonb;
BEGIN
 base:=zasp_authorization80.agent_posture(o,w,e,i);
 IF base IS NULL OR base='null'::jsonb THEN RETURN 'null'::jsonb; END IF;
 SELECT jsonb_agg(jsonb_build_object('purpose',j.purpose,'state',CASE
  WHEN j.finished_at IS NOT NULL AND j.result IS NOT NULL AND j.summary=zasp_authorization80.inventory_review_summary(o,w,e,i,j.purpose) THEN 'reviewed'
  WHEN j.finished_at IS NOT NULL OR j.expires_at<=now() OR j.created_at<=now()-interval '1 day' THEN 'uncertain' ELSE 'pending' END,
  'evidence_id',j.evidence_id,'result',CASE WHEN j.summary=zasp_authorization80.inventory_review_summary(o,w,e,i,j.purpose) THEN j.result END) ORDER BY j.purpose) INTO reviews
 FROM public.zasp_discovery_sync_reviews j JOIN public.zasp_inventory_entities a ON
 (a.organization_id,a.workspace_id,a.environment_id,a.id,a.winning_evidence_id,a.winning_integration_id,a.winning_snapshot_id)=(j.organization_id,j.workspace_id,j.environment_id,j.agent_id,j.evidence_id,j.integration_id,j.snapshot_id)
 WHERE (j.organization_id,j.workspace_id,j.environment_id,j.agent_id)=(o,w,e,i);
 RETURN base||jsonb_build_object('sync_reviews',coalesce(reviews,'[]'::jsonb));
END $posture$;
ALTER FUNCTION zasp_authorization80.agent_posture_with_sync(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.agent_posture_with_sync(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.agent_posture_with_sync(text,text,text,text) TO zasp_discovery_api;
