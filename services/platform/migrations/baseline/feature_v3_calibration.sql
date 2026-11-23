-- Evidence contains labels, identifiers and scores. No interaction text is retained.
CREATE TABLE IF NOT EXISTS public.analyst_feedback (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,decision_id text NOT NULL,rule_id text NOT NULL,
 label text NOT NULL CHECK(label IN('confirm_tp','mark_fp')), actor text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,decision_id,rule_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,decision_id) REFERENCES public.zasp_guardrail_decisions ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS public.semantic_evaluations (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,decision_id text NOT NULL,rule_id text NOT NULL,
 threat_probability numeric NOT NULL CHECK(threat_probability BETWEEN 0 AND 1),
 serious boolean NOT NULL, deployment_digest text NOT NULL CHECK(deployment_digest ~ '^sha256:[a-f0-9]{64}$'), evaluated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,decision_id,rule_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,decision_id) REFERENCES public.zasp_guardrail_decisions ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS public.rule_suppression_states (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,rule_id text NOT NULL,
 mode text NOT NULL CHECK(mode IN('off','shadow','active')),version bigint NOT NULL CHECK(version>0),
 shadow_since timestamptz NOT NULL DEFAULT now(), actor text NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,rule_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
CREATE TABLE IF NOT EXISTS public.zasp_calibration_mutations (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,actor text NOT NULL,idem text NOT NULL,
 request_values jsonb NOT NULL, result jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,actor,idem),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
CREATE TABLE IF NOT EXISTS public.zasp_discovery_calibration_labels (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL, sample_id text NOT NULL,
 evaluated_at timestamptz NOT NULL DEFAULT now(), observed_deployment boolean NOT NULL,predicted_deployment boolean NOT NULL,
 PRIMARY KEY(organization_id,workspace_id,environment_id,sample_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_data_controls
);
DO $tables$ DECLARE tbl text; BEGIN
 FOREACH tbl IN ARRAY ARRAY['analyst_feedback','semantic_evaluations','rule_suppression_states','zasp_calibration_mutations','zasp_discovery_calibration_labels'] LOOP
 EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',tbl);
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tbl);
 EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tbl);
 EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tbl);
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename=tbl AND policyname='calibration_owner') THEN
 EXECUTE format('CREATE POLICY calibration_owner ON public.%I TO zasp_discovery_authority USING(true) WITH CHECK(true)',tbl);
 END IF;
 END LOOP;
END $tables$;

CREATE OR REPLACE FUNCTION zasp_authorization80.calibration_metrics(o text,w text,e text) RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $metrics$
DECLARE result jsonb;
BEGIN
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'getCalibrationMetrics','view','environment',e,false,true,false,false);
 WITH observations AS MATERIALIZED (
 SELECT s.threat_probability AS p, (f.label='confirm_tp')::int AS y FROM public.semantic_evaluations s
 LEFT JOIN public.analyst_feedback f USING(organization_id,workspace_id,environment_id,decision_id,rule_id)
 WHERE (s.organization_id,s.workspace_id,s.environment_id)=(o,w,e) AND s.evaluated_at>=now()-interval '30 days'
 ), buckets AS (SELECT floor(p*10)::int AS bucket, count(*) AS n,sum(p) AS psum,sum(y) AS positives,sum((p-y)^2) AS squares FROM observations WHERE y IS NOT NULL GROUP BY 1),
 recent AS (SELECT d.id AS decision_id,m->>'id' AS rule_id,d.created_at AS occurred_at,f.label
 FROM (SELECT * FROM public.zasp_guardrail_decisions WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND created_at>=now()-interval '30 days' AND jsonb_array_length(rules)>0 ORDER BY created_at DESC,id LIMIT 30) d
 CROSS JOIN LATERAL jsonb_array_elements(d.rules) m LEFT JOIN public.analyst_feedback f ON (f.organization_id,f.workspace_id,f.environment_id,f.decision_id,f.rule_id)=(o,w,e,d.id,m->>'id')
 ORDER BY d.created_at DESC,d.id,rule_id LIMIT 30),
 discovery AS (SELECT count(*) FILTER(WHERE observed_deployment AND predicted_deployment) AS tp,
 count(*) FILTER(WHERE NOT observed_deployment AND predicted_deployment) AS fp,count(*) FILTER(WHERE observed_deployment AND NOT predicted_deployment) AS fn
 FROM public.zasp_discovery_calibration_labels WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND evaluated_at>=now()-interval '30 days')
 SELECT jsonb_build_object('environment_id',e,'evaluated',(SELECT count(*) FROM observations),
 'labelled',(SELECT count(*) FROM public.analyst_feedback WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND created_at>=now()-interval '30 days'),
 'buckets',coalesce((SELECT jsonb_agg(to_jsonb(b) ORDER BY bucket) FROM buckets b),'[]'::jsonb),
 'discovery',(SELECT to_jsonb(d) FROM discovery d),'recent',coalesce((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.occurred_at DESC,r.decision_id,r.rule_id) FROM recent r),'[]'::jsonb))
 INTO result;
 RETURN result;
END $metrics$;

CREATE OR REPLACE FUNCTION zasp_authorization80.suppression_state(o text,w text,e text,r text) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $state$
 WITH state AS (SELECT mode,version,shadow_since FROM public.rule_suppression_states WHERE (organization_id,workspace_id,environment_id,rule_id)=(o,w,e,r)),
 flags AS (SELECT s.serious,s.threat_probability<0.5 AS benign,f.label
 FROM public.semantic_evaluations s JOIN public.analyst_feedback f USING(organization_id,workspace_id,environment_id,decision_id,rule_id)
 JOIN public.zasp_environment_ai_controls env USING(organization_id,workspace_id,environment_id) JOIN public.zasp_organization_ai_controls org USING(organization_id)
 JOIN public.model_qualifications q USING(organization_id,workspace_id,environment_id)
 WHERE (s.organization_id,s.workspace_id,s.environment_id,s.rule_id)=(o,w,e,r) AND s.evaluated_at>=(SELECT shadow_since FROM state)
 AND org.ai_enabled AND env.mode=ANY(org.allowed_modes) AND env.mode IN('zasp_vpc_slm','byoc_self_hosted') AND env.tier2_heuristic_fp_suppression_enabled
 AND q.provider=env.mode AND q.model=env.tier2_profile AND q.purpose='heuristic_fp_verify' AND q.qualified AND q.expires_at>now() AND q.deployment_digest=s.deployment_digest),
 counts AS (SELECT count(*) AS n,count(*) FILTER(WHERE benign AND label='mark_fp') AS avoided, count(*) FILTER(WHERE serious AND label='confirm_tp') AS total, count(*) FILTER(WHERE serious AND benign AND label='confirm_tp') AS missed FROM flags)
 SELECT jsonb_build_object('rule_id',r,'rule_class',CASE WHEN r IN('injection.instruction_override','injection.role_switch','injection.hidden_text','injection.tool_call') THEN 'heuristic' ELSE 'hard' END,
 'mode',coalesce((SELECT mode FROM state),'off'),'version',coalesce((SELECT version FROM state),0),'shadow_labels',n,'false_alerts_avoided',avoided,'serious_total',total,'serious_missed',missed,
 'eligible',coalesce((SELECT mode FROM state),'off') IN('shadow','active') AND n>=60 AND avoided>0 AND total>=1 AND missed=0) FROM counts
$state$;

CREATE OR REPLACE FUNCTION zasp_authorization80.calibration_action(o text,w text,e text,a text,op text,r text,d text,v text,expected bigint,k text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $action$
DECLARE proof jsonb; state jsonb; prior public.zasp_calibration_mutations%ROWTYPE; args jsonb:=jsonb_build_array(op,r,d,v,expected);
BEGIN
 IF op NOT IN('submitAnalystFeedback','getRuleSuppressionMode','putRuleSuppressionMode') OR op IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF r IS NULL OR r NOT IN('injection.instruction_override','injection.role_switch','injection.hidden_text','injection.tool_call','pii.email','pii.phone','pii.credit_card','pii.us_ssn','secret.aws_access_key_id','secret.private_key','secret.bearer_token') THEN RETURN 'null'::jsonb; END IF;
 IF op='getRuleSuppressionMode' THEN
  proof:=zasp_authorization80.product_request(o,w,e,a,op,'view','environment',e,false,true,false,false);
 ELSE
  proof:=zasp_authorization80.product_request(o,w,e,a,op,'manage_workflows','environment',e,false,true,true,true);
 END IF;
 IF op IN('getRuleSuppressionMode','putRuleSuppressionMode') AND proof#>>'{path_parameters,ruleId}' IS DISTINCT FROM r THEN RAISE EXCEPTION USING ERRCODE='42501'; END IF;
 IF op='getRuleSuppressionMode' THEN RETURN zasp_authorization80.suppression_state(o,w,e,r); END IF;
 IF k IS NULL OR length(k) NOT BETWEEN 16 AND 128 THEN RETURN '"invalid"'::jsonb; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,'calibration'),0));
 SELECT * INTO prior FROM public.zasp_calibration_mutations WHERE (organization_id,workspace_id,environment_id,actor,idem)=(o,w,e,a,k);
 IF FOUND THEN IF prior.request_values=args THEN RETURN prior.result; ELSE RETURN '"conflict"'::jsonb; END IF; END IF;
 IF op='submitAnalystFeedback' THEN
  IF v IS NULL OR v NOT IN('mark_fp','confirm_tp') THEN RETURN '"invalid"'::jsonb; END IF;
  IF NOT EXISTS(SELECT FROM public.zasp_guardrail_decisions g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.id)=(o,w,e,d) AND g.rules @>jsonb_build_array(jsonb_build_object('id',r))) THEN RETURN 'null'::jsonb; END IF;
  INSERT INTO public.analyst_feedback VALUES(o,w,e,d,r,v,a,now()) ON CONFLICT(organization_id,workspace_id,environment_id,decision_id,rule_id)
  DO UPDATE SET label=excluded.label,actor=excluded.actor,created_at=now();
  state:=jsonb_build_object('decision_id',d,'rule_id',r,'label',v);
 ELSE
  state:=zasp_authorization80.suppression_state(o,w,e,r);
  IF expected IS DISTINCT FROM (state->>'version')::bigint THEN RETURN '"conflict"'::jsonb; END IF;
  IF v IS NULL OR v NOT IN('off','shadow','active') OR (state->>'rule_class'='hard' AND v<>'off') OR
   (v='active' AND (state->>'eligible')::boolean IS NOT TRUE) THEN RETURN '"invalid"'::jsonb; END IF;
  IF v<>state->>'mode' THEN
   INSERT INTO public.rule_suppression_states AS s VALUES(o,w,e,r,v,expected+1,now(),a) ON CONFLICT(organization_id,workspace_id,environment_id,rule_id)
   DO UPDATE SET mode=excluded.mode,version=excluded.version,actor=excluded.actor,shadow_since=CASE WHEN excluded.mode='shadow' THEN now() ELSE s.shadow_since END;
   state:=zasp_authorization80.suppression_state(o,w,e,r);
  END IF;
 END IF;
 INSERT INTO public.zasp_calibration_mutations VALUES(o,w,e,a,k,args,state,now());
 PERFORM zasp_authorization80.product_settled(proof);
 RETURN state;
END $action$;
ALTER FUNCTION zasp_authorization80.suppression_state(text,text,text,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.calibration_action(text,text,text,text,text,text,text,text,bigint,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION zasp_authorization80.calibration_metrics(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.suppression_state(text,text,text,text),zasp_authorization80.calibration_action(text,text,text,text,text,text,text,text,bigint,text),zasp_authorization80.calibration_metrics(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.calibration_action(text,text,text,text,text,text,text,text,bigint,text),zasp_authorization80.calibration_metrics(text,text,text) TO zasp_discovery_api;
