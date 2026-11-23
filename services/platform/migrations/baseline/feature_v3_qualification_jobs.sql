-- Only the trusted release runner registers signed profiles and writes measured
-- outcomes. The browser selects a tuple; it cannot supply fixtures or a verdict.
CREATE TABLE IF NOT EXISTS public.model_qualification_workers (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 provider text NOT NULL,model text NOT NULL,purpose text NOT NULL,deployment_digest text NOT NULL CHECK(deployment_digest~'^sha256:[a-f0-9]{64}$'),
 region text NOT NULL CHECK(region IN('us','eu')),cost_per_call bigint NOT NULL CHECK(cost_per_call BETWEEN 1 AND 9007199254740991),
 available_until timestamptz NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,provider,model,purpose),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
CREATE TABLE IF NOT EXISTS public.model_qualification_runs (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,id text NOT NULL,
 provider text NOT NULL,model text NOT NULL,purpose text NOT NULL,deployment_digest text NOT NULL,
 actor text NOT NULL,idem text NOT NULL,status text NOT NULL CHECK(status IN('queued','running','passed','failed')),
 requested_at timestamptz NOT NULL DEFAULT now(),finished_at timestamptz,lease uuid,
 PRIMARY KEY(organization_id,workspace_id,environment_id,id),UNIQUE(organization_id,workspace_id,environment_id,actor,idem),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
CREATE INDEX IF NOT EXISTS zasp_qualification_pending ON public.model_qualification_runs(organization_id,workspace_id,environment_id,provider,model,purpose,requested_at) WHERE status IN('queued','running');
DO $workers$ DECLARE tbl text; BEGIN
 FOREACH tbl IN ARRAY ARRAY['model_qualification_workers','model_qualification_runs'] LOOP
 EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',tbl);
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tbl);
 EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tbl);
 EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tbl);
 IF NOT EXISTS (SELECT FROM pg_policies WHERE schemaname='public' AND tablename=tbl AND policyname='qualification_owner') THEN
 EXECUTE format('CREATE POLICY qualification_owner ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',tbl);
 END IF; END LOOP;
END $workers$;

CREATE OR REPLACE FUNCTION zasp_authorization80.qualification_policy(o text,w text,e text,prov text,m text,reg text) RETURNS bigint
LANGUAGE sql VOLATILE SET search_path=pg_catalog,public AS $qp$
 SELECT env.monthly_budget_nano_credits FROM public.zasp_environment_ai_controls env JOIN public.zasp_organization_ai_controls org USING(organization_id)
 WHERE (env.organization_id,env.workspace_id,env.environment_id)=(o,w,e) AND org.ai_enabled AND org.require_zero_retention AND env.mode=prov AND prov=ANY(org.allowed_modes)
 AND (org.allowed_residency IN('us_eu',reg||'_only') OR (org.allowed_residency='customer_vpc_only' AND prov='byoc_self_hosted'))
 AND reg IN('us','eu') AND env.monthly_budget_nano_credits>0 AND
 ((prov IN('zasp_vpc_slm','byoc_self_hosted') AND env.tier2_profile=m) OR (prov IN('privatelink_vertex','privatelink_bedrock') AND env.tier3_model_pin=m))
 FOR SHARE OF env,org
$qp$;

CREATE OR REPLACE FUNCTION zasp_authorization80.qualification_job(o text,w text,e text,a text,id_value text,prov text,m text,p text,k text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $qj$
DECLARE j public.model_qualification_runs%ROWTYPE;worker public.model_qualification_workers%ROWTYPE;proof jsonb;time_limit timestamptz;
BEGIN
 IF k IS NULL THEN
  proof:=zasp_authorization80.product_request(o,w,e,a,'getModelQualificationRun','view_compliance','environment',e,false,true,false,false);
  IF proof#>>'{path_parameters,id}' IS DISTINCT FROM id_value THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
  SELECT * INTO j FROM public.model_qualification_runs WHERE (organization_id,workspace_id,environment_id,id)=(o,w,e,id_value);
  IF NOT FOUND THEN RETURN 'null'; END IF;
 ELSE
  proof:=zasp_authorization80.product_request(o,w,e,a,'runModelQualification','manage_data_controls','environment',e,false,true,true,true);
  IF k !~'^[A-Za-z0-9_.:-]{16,128}$' THEN RETURN '"invalid"'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,'qualifications'),0));
  SELECT * INTO j FROM public.model_qualification_runs WHERE (organization_id,workspace_id,environment_id,actor,idem)=(o,w,e,a,k);
  IF FOUND THEN
   IF (j.provider,j.model,j.purpose) IS DISTINCT FROM (prov,m,p) THEN RETURN '"conflict"'; END IF;
  ELSE
   SELECT * INTO worker FROM public.model_qualification_workers WHERE (organization_id,workspace_id,environment_id,provider,model,purpose)=(o,w,e,prov,m,p) AND available_until>now() FOR SHARE;
   IF NOT FOUND OR zasp_authorization80.qualification_policy(o,w,e,prov,m,worker.region) IS NULL THEN RETURN '"unavailable"'; END IF;
   IF EXISTS(SELECT FROM public.model_qualification_runs x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.provider,x.model,x.purpose)=(o,w,e,prov,m,p) AND x.status IN('queued','running') AND x.requested_at>now()-interval '1 hour') THEN RETURN '"conflict"'; END IF;
   INSERT INTO public.model_qualification_runs(organization_id,workspace_id,environment_id,id,provider,model,purpose,deployment_digest,actor,idem,status)
    VALUES(o,w,e,id_value,prov,m,p,worker.deployment_digest,a,k,'queued') RETURNING * INTO j;
  END IF;
  PERFORM zasp_authorization80.product_settled(proof);
 END IF;
 time_limit:=j.requested_at+interval '1 hour';
 IF j.status IN('queued','running') AND time_limit<=now() THEN j.status:='failed';j.finished_at:=time_limit;END IF;
 RETURN jsonb_build_object('id',j.id,'environment_id',e,'provider',j.provider,'model',j.model,'purpose',j.purpose,'status',j.status,'requested_at',j.requested_at,'finished_at',j.finished_at);
END $qj$;

CREATE OR REPLACE FUNCTION zasp_authorization80.qualify_observation(o text,w text,e text,j text,t uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,public AS $observation$
DECLARE profile record;cap bigint;month_key date:=date_trunc('month',now() AT TIME ZONE 'UTC')::date;
BEGIN
 SELECT wr.* INTO profile FROM public.model_qualification_runs r JOIN public.model_qualification_workers wr USING(organization_id,workspace_id,environment_id,provider,model,purpose,deployment_digest)
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.id,r.lease)=(o,w,e,j,t) AND r.status='running' AND r.requested_at>now()-interval '1 hour';
 IF NOT FOUND THEN RETURN false;END IF;
 cap:=zasp_authorization80.qualification_policy(o,w,e,profile.provider,profile.model,profile.region);
 IF cap IS NULL OR cap<profile.cost_per_call THEN RETURN false; END IF;
 INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(o,w,e,month_key,profile.cost_per_call)
 ON CONFLICT(organization_id,workspace_id,environment_id,month_start) DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+profile.cost_per_call WHERE u.reserved_nano_credits<=cap-profile.cost_per_call;
 RETURN FOUND;
END $observation$;
ALTER FUNCTION zasp_authorization80.qualification_policy(text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.qualify_observation(text,text,text,text,uuid) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.qualification_job(text,text,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.qualification_policy(text,text,text,text,text,text),zasp_authorization80.qualify_observation(text,text,text,text,uuid),zasp_authorization80.qualification_job(text,text,text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.qualification_job(text,text,text,text,text,text,text,text,text) TO zasp_discovery_api;
