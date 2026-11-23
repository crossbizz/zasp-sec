-- Conversations are private to their author and the authorized session. A
-- pending turn is immutable and single-use, even after an interrupted stream.
CREATE TABLE IF NOT EXISTS public.zasp_security_agent_chat_threads (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 owner_id text NOT NULL, session_id text NOT NULL, id text NOT NULL, studio_id text, studio_revision bigint,
 CHECK((studio_id IS NULL)=(studio_revision IS NULL)), created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,owner_id,session_id,id)
);
CREATE TABLE IF NOT EXISTS public.zasp_security_agent_chat_messages (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,owner_id text NOT NULL,session_id text NOT NULL,
 thread_id text NOT NULL,request_id text NOT NULL,assistant_id text NOT NULL,
 question text NOT NULL CHECK(length(question) BETWEEN 1 AND 1000),created_at timestamptz NOT NULL DEFAULT now(),
 status text NOT NULL CHECK(status IN('pending','answered','failed')),
 answer text CHECK(length(answer) BETWEEN 1 AND 4096),evidence_ids jsonb,finished_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,owner_id,session_id,thread_id,request_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,owner_id,session_id,thread_id)
 REFERENCES public.zasp_security_agent_chat_threads,
 CHECK((status='answered')=(answer IS NOT NULL AND evidence_ids IS NOT NULL)),
 CHECK((status='pending')=(finished_at IS NULL))
);
DO $chat_rls$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['zasp_security_agent_chat_threads','zasp_security_agent_chat_messages'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',t);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',t);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=t AND policyname='chat_authority') THEN
   EXECUTE format('CREATE POLICY chat_authority ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',t);
  END IF;
 END LOOP;
END $chat_rls$;

-- Verify effective consent at each admission/readback. The model dispatch also
-- pins residency, credential material, model and the qualified deployment.
CREATE OR REPLACE FUNCTION zasp_authorization80.chat_allowed(o text,w text,e text,config jsonb) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $allowed$
 SELECT EXISTS(
  SELECT FROM public.zasp_organization_ai_controls org
  JOIN public.zasp_environment_ai_controls env USING(organization_id)
  JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
  WHERE (env.organization_id,env.workspace_id,env.environment_id)=(o,w,e)
   AND org.ai_enabled AND org.require_zero_retention AND env.mode=ANY(org.allowed_modes)
   AND env.mode IN ('privatelink_bedrock','privatelink_vertex') AND env.tier3_provider=env.mode AND env.tier3_security_agent_planner_enabled
   AND env.allow_redacted_summaries AND env.monthly_budget_nano_credits>0
   AND q.provider=env.mode AND q.model=env.tier3_model_pin AND q.purpose='security_agent_triage'
   AND q.qualified AND q.deployment_digest IS NOT NULL AND q.checked_at<=now() AND q.expires_at>now()
   AND (zasp_authorization80.ai_data_limits(o,w,e,false)->>'collection_mode') IN('extended','metadata_only')
   AND org.allowed_residency IN('us_only','eu_only','us_eu')
   AND (config IS NULL OR (env.mode=config->>'provider' AND env.tier3_model_pin=config->>'model' AND org.allowed_residency IN ('us_eu',(config->>'region')||'_only')
     AND env.credential_digest=config->>'credential_digest' AND env.credential_reference=config->>'credential_reference'
     AND q.deployment_digest=config->>'deployment_digest'))
   AND EXISTS(SELECT FROM public.zasp_security_agent_kill_switches k WHERE (k.organization_id,k.workspace_id,k.environment_id,k.action_key,k.execution_enabled)=('*','*','*','*',true))
   AND EXISTS(SELECT FROM public.zasp_security_agent_kill_switches k WHERE (k.organization_id,k.workspace_id,k.environment_id,k.action_key,k.execution_enabled)=(o,w,e,'*',true))
 );
$allowed$;

CREATE OR REPLACE FUNCTION zasp_authorization80.analyst_threads(o text,w text,e text,a text,s text,op text,t text,studio text,revision bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $threads$
DECLARE proof jsonb; value jsonb; history jsonb; profile jsonb;
BEGIN
 IF op NOT IN('getAnalystThreads','getAnalystThread','createAnalystThread') THEN RAISE EXCEPTION USING ERRCODE='22023';END IF;
 proof:=zasp_authorization80.product_request(o,w,e,a,op,'investigate_sessions','session',s,false,true,false,op='createAnalystThread');
 IF op='getAnalystThread' AND proof#>>'{path_parameters,id}' IS DISTINCT FROM t THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF NOT zasp_authorization80.chat_allowed(o,w,e,NULL) THEN RETURN '"disabled"'::jsonb; END IF;
 IF op='getAnalystThreads' THEN
  SELECT jsonb_build_object('items',coalesce(jsonb_agg(to_jsonb(rows) ORDER BY created_at DESC,id DESC),'[]'::jsonb)) INTO value FROM
   (SELECT x.id,x.session_id,x.created_at FROM public.zasp_security_agent_chat_threads x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id)=(o,w,e,a,s) ORDER BY created_at DESC,id DESC LIMIT 50) rows;
  RETURN value;
 END IF;
 IF op='createAnalystThread' THEN
  IF t IS NULL OR length(t) NOT BETWEEN 16 AND 128 THEN RAISE EXCEPTION USING ERRCODE='22023'; END IF;
  t:=public.zasp_discovery_canonical_id(o,w,e,'analyst_thread',concat_ws('/',a,s,t));
  IF studio IS NOT NULL THEN
   profile:=zasp_authorization80.studio_revision(o,w,e,studio,0);
   IF profile IS NULL OR profile->>'id' IS DISTINCT FROM studio OR (profile->>'revision')::bigint IS DISTINCT FROM revision
    OR profile#>>'{definition,trigger}' IS DISTINCT FROM 'manual' OR NOT coalesce((profile#>'{definition,read_tools}')?'inspect_session',false)
    OR coalesce((profile#>>'{definition,max_steps}')::int,0)<1 THEN RETURN '"ineligible"'::jsonb; END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,a,s,'chat'),0));
  IF EXISTS(SELECT FROM public.zasp_security_agent_chat_threads x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.id)=(o,w,e,a,s,t)
   AND (x.studio_id,x.studio_revision) IS DISTINCT FROM (studio,revision)) THEN RETURN '"conflict"'::jsonb;END IF;
  IF NOT EXISTS(SELECT FROM public.zasp_security_agent_chat_threads x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.id)=(o,w,e,a,s,t)) AND (SELECT count(*) FROM public.zasp_security_agent_chat_threads x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id)=(o,w,e,a,s))>=50 THEN RETURN '"limit"'::jsonb;END IF;
  INSERT INTO public.zasp_security_agent_chat_threads(organization_id,workspace_id,environment_id,owner_id,session_id,id,studio_id,studio_revision) VALUES(o,w,e,a,s,t,studio,revision) ON CONFLICT DO NOTHING;
  PERFORM zasp_authorization80.product_settled(proof);
 END IF;
 SELECT jsonb_build_object('id',x.id,'session_id',s,'created_at',x.created_at) INTO value FROM public.zasp_security_agent_chat_threads x
 WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.id)=(o,w,e,a,s,t);
 IF value IS NULL THEN RETURN 'null'::jsonb; END IF;
 IF op='getAnalystThread' THEN
  SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.created_at,m.role DESC,m.id),'[]'::jsonb) INTO history FROM (
   SELECT v.* FROM public.zasp_security_agent_chat_messages x CROSS JOIN LATERAL (VALUES
    (x.request_id,'user',x.question,x.created_at,'[]'::jsonb),(x.assistant_id,'assistant',x.answer,x.finished_at,x.evidence_ids)) v(id,role,text,created_at,evidence_ids)
   WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.status)=(o,w,e,a,s,t,'answered')) m;
  value:=value||jsonb_build_object('messages',history);
 END IF;
 RETURN value;
END $threads$;

CREATE OR REPLACE FUNCTION zasp_authorization80.analyst_turn(o text,w text,e text,a text,s text,t text,k text,q jsonb,cfg jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $turn$
DECLARE proof jsonb; prior public.zasp_security_agent_chat_messages%ROWTYPE;assistant text; cost bigint; cap bigint;
 pinned public.zasp_security_agent_chat_threads%ROWTYPE; profile jsonb; month_key date:=date_trunc('month',now() AT TIME ZONE 'UTC')::date;content jsonb;
BEGIN
 proof:=zasp_authorization80.product_request(o,w,e,a,'streamAnalystThread','investigate_sessions','session',s,false,true,false,true);
 IF proof#>>'{path_parameters,id}' IS DISTINCT FROM t OR NOT public.zasp_valid_product_id(k) THEN RAISE EXCEPTION USING ERRCODE='42501';END IF;
 IF cfg IS NULL OR NOT zasp_authorization80.chat_allowed(o,w,e,cfg) THEN RETURN '"disabled"'::jsonb; END IF;
 SELECT * INTO pinned FROM public.zasp_security_agent_chat_threads x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.id)=(o,w,e,a,s,t) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 IF pinned.studio_id IS NOT NULL THEN
  profile:=zasp_authorization80.studio_revision(o,w,e,pinned.studio_id,0);
  IF (profile->>'revision')::bigint IS DISTINCT FROM pinned.studio_revision OR profile#>>'{definition,model_pin}' IS DISTINCT FROM cfg->>'model'
   OR coalesce((profile#>>'{definition,budget_nano_credits}')::bigint,0)<(cfg->>'cost')::bigint THEN RETURN '"disabled"'::jsonb;END IF;
 END IF;
 SELECT * INTO prior FROM public.zasp_security_agent_chat_messages x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.request_id)=(o,w,e,a,s,t,k);
 IF q->>'phase'='start' THEN
  IF NOT coalesce(length(q->>'question') BETWEEN 1 AND 1000 AND public.zasp_valid_product_id(q->>'assistant_id'),false) THEN RAISE EXCEPTION USING ERRCODE='22023';END IF;
  IF prior.request_id IS NOT NULL THEN
   IF prior.question IS DISTINCT FROM q->>'question' OR prior.status<>'answered' THEN RETURN '"conflict"'::jsonb;END IF;
   RETURN jsonb_build_object('assistant_id',prior.assistant_id,'text',prior.answer,'evidence_ids',prior.evidence_ids);
  END IF;
  IF EXISTS(SELECT FROM public.zasp_security_agent_chat_messages x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.status)=(o,w,e,a,s,t,'pending') AND x.created_at>now()-interval '2 minutes') THEN RETURN '"conflict"'::jsonb;END IF;
  IF (SELECT count(*) FROM public.zasp_security_agent_chat_messages x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id)=(o,w,e,a,s,t))>=24 THEN RETURN '"limit"'::jsonb;END IF;
  cost:=(cfg->>'cost')::bigint;
  SELECT monthly_budget_nano_credits INTO cap FROM public.zasp_environment_ai_controls WHERE (organization_id,workspace_id,environment_id)=(o,w,e) FOR SHARE;
  IF cost IS NULL OR cost<=0 OR cap IS NULL OR cost>cap THEN RETURN '"budget"'::jsonb;END IF;
  content:=zasp_authorization80.session_intent_evidence(o,w,e,s);
  IF content IS NULL OR content='null'::jsonb OR jsonb_array_length(content)=0 THEN RETURN '"no_evidence"'::jsonb;END IF;
  INSERT INTO public.zasp_ai_monthly_usage AS u VALUES(o,w,e,month_key,cost) ON CONFLICT(organization_id,workspace_id,environment_id,month_start)
  DO UPDATE SET reserved_nano_credits=u.reserved_nano_credits+cost WHERE u.reserved_nano_credits<=cap-cost;
  IF NOT FOUND THEN RETURN '"budget"'::jsonb;END IF;
  INSERT INTO public.zasp_security_agent_chat_messages(organization_id,workspace_id,environment_id,owner_id,session_id,thread_id,request_id,assistant_id,question,status)
  VALUES(o,w,e,a,s,t,k,q->>'assistant_id',q->>'question','pending');
  PERFORM zasp_authorization80.product_settled(proof);
  RETURN jsonb_build_object('assistant_id',q->>'assistant_id','evidence',content);
 END IF;
 IF prior.status IS DISTINCT FROM 'pending' OR prior.assistant_id IS DISTINCT FROM q->>'assistant_id' OR prior.created_at<now()-interval '2 minutes' THEN RETURN '"conflict"'::jsonb; END IF;
 IF q->>'phase'='finish' AND length(q->>'text') BETWEEN 1 AND 4096 AND jsonb_typeof(q->'evidence_ids')='array' AND jsonb_array_length(q->'evidence_ids') BETWEEN 1 AND 6 THEN
  UPDATE public.zasp_security_agent_chat_messages x SET status='answered',answer=q->>'text',evidence_ids=q->'evidence_ids',finished_at=clock_timestamp()
   WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.request_id)=(o,w,e,a,s,t,k);
 ELSIF q->>'phase'='fail' THEN
  UPDATE public.zasp_security_agent_chat_messages x SET status='failed',finished_at=clock_timestamp() WHERE (x.organization_id,x.workspace_id,x.environment_id,x.owner_id,x.session_id,x.thread_id,x.request_id)=(o,w,e,a,s,t,k);
 ELSE RAISE EXCEPTION USING ERRCODE='22023';END IF;
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN jsonb_build_object('assistant_id',prior.assistant_id,'text',q->>'text','evidence_ids',q->'evidence_ids');
END $turn$;
DO $chat_grants$ DECLARE f text; BEGIN
 FOREACH f IN ARRAY ARRAY['chat_allowed(text,text,text,jsonb)','analyst_threads(text,text,text,text,text,text,text,text,bigint)','analyst_turn(text,text,text,text,text,text,text,jsonb,jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION zasp_authorization80.%s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION zasp_authorization80.%s FROM PUBLIC',f);
  IF f NOT LIKE 'chat_allowed%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION zasp_authorization80.%s TO zasp_discovery_api',f);END IF;
 END LOOP;
END $chat_grants$;
