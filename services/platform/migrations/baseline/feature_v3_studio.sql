-- Studio revisions are immutable. A thread pins a revision, and its runner
-- independently resolves current authorization and model qualification.
CREATE TABLE IF NOT EXISTS public.zasp_custom_security_agent_revisions (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 id text NOT NULL CHECK(public.zasp_valid_product_id(id)),revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'),actor text NOT NULL,request_key text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,id,revision),
 UNIQUE(organization_id,workspace_id,environment_id,actor,request_key),
 FOREIGN KEY(organization_id,workspace_id,environment_id) REFERENCES public.zasp_environments(organization_id,workspace_id,id)
);
ALTER TABLE public.zasp_custom_security_agent_revisions OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_custom_security_agent_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_custom_security_agent_revisions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_custom_security_agent_revisions FROM PUBLIC;
DO $policy$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_custom_security_agent_revisions' AND policyname='studio_authority') THEN
  CREATE POLICY studio_authority ON public.zasp_custom_security_agent_revisions TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy$;

CREATE OR REPLACE FUNCTION zasp_authorization80.studio_revision(o text,w text,e text,i text,rev bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $revision$
 SELECT jsonb_build_object('id',id,'revision',revision,'definition',definition) FROM public.zasp_custom_security_agent_revisions r
 WHERE (r.organization_id,r.workspace_id,r.environment_id,r.id)=(o,w,e,i) AND (rev=0 OR r.revision=rev) ORDER BY r.revision DESC LIMIT 1
$revision$;
CREATE OR REPLACE FUNCTION zasp_authorization80.studio_valid(d jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public AS $valid$
DECLARE keys text[]:=ARRAY['name','mission','trigger','read_tools','proposal','require_approval','max_steps','budget_nano_credits','model_pin']; attr text;
BEGIN
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR NOT (d ?& keys) OR d-keys-'approval_required_tools'-'minimum_evidence_confidence'<>'{}' OR octet_length(d::text)>8192 THEN RETURN false; END IF;
 FOREACH attr IN ARRAY ARRAY['name','mission','trigger','proposal','model_pin'] LOOP
  IF jsonb_typeof(d->attr) IS DISTINCT FROM 'string' OR d->>attr<>btrim(d->>attr) OR (d->>attr) ~ '[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 IF length(d->>'name') NOT BETWEEN 1 AND 80 OR length(d->>'mission') NOT BETWEEN 1 AND 512 OR length(d->>'model_pin')>128
 OR d->>'trigger' NOT IN ('manual','finding_opened') OR d->>'proposal' NOT IN ('none','propose_policy','request_containment')
 OR d->'require_approval' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(d->'read_tools') IS DISTINCT FROM 'array'
 OR jsonb_typeof(d->'max_steps') IS DISTINCT FROM 'number' OR (d->>'max_steps')!~'^[1-6]$'
 OR jsonb_typeof(d->'budget_nano_credits') IS DISTINCT FROM 'number' OR (d->>'budget_nano_credits')!~'^(0|[1-9][0-9]{0,12})$' THEN RETURN false; END IF;
 IF d?'minimum_evidence_confidence' AND (jsonb_typeof(d->'minimum_evidence_confidence') IS DISTINCT FROM 'string' OR d->>'minimum_evidence_confidence' NOT IN ('strong','exact')) THEN RETURN false; END IF;
 IF d?'approval_required_tools' THEN
  IF jsonb_typeof(d->'approval_required_tools') IS DISTINCT FROM 'array' OR jsonb_array_length(d->'approval_required_tools')>4 OR NOT ((d->'read_tools') @> (d->'approval_required_tools')) THEN RETURN false; END IF;
  IF EXISTS(SELECT FROM jsonb_array_elements_text(d->'approval_required_tools') t GROUP BY t HAVING count(*)>1) THEN RETURN false; END IF;
 END IF;
 RETURN (d->>'budget_nano_credits')::bigint<=1000000000000 AND jsonb_array_length(d->'read_tools') BETWEEN 1 AND 4
 AND (SELECT count(DISTINCT t)=count(*) AND bool_and(t IN ('list_agents','get_posture_summary','inspect_session','get_addon_drift'))
      FROM jsonb_array_elements_text(d->'read_tools') t);
END $valid$;

CREATE OR REPLACE FUNCTION zasp_authorization80.studio_read(o text,w text,e text,i text,after_id text,n integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $read$
DECLARE p jsonb; page jsonb;
BEGIN
 IF i IS NOT NULL THEN
  p:=zasp_authorization80.product_request(o,w,e,NULL,'getCustomSecurityAgent','view','environment',e,false,true,false,false);
  IF p#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong Studio agent'; END IF;
  RETURN coalesce(zasp_authorization80.studio_revision(o,w,e,i,0),'null'::jsonb);
 END IF;
 PERFORM zasp_authorization80.product_request(o,w,e,NULL,'listCustomSecurityAgents','view','environment',e,false,true,false,false);
 IF n IS NULL OR n NOT BETWEEN 1 AND 100 OR (after_id IS NOT NULL AND NOT public.zasp_valid_product_id(after_id)) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid page'; END IF;
 WITH candidate AS MATERIALIZED (
  SELECT DISTINCT ON(r.id) r.id,r.revision,r.definition FROM public.zasp_custom_security_agent_revisions r
  WHERE (r.organization_id,r.workspace_id,r.environment_id)=(o,w,e) AND (after_id IS NULL OR r.id>after_id)
  ORDER BY r.id,r.revision DESC LIMIT n+1
 ), visible AS (SELECT * FROM candidate ORDER BY id LIMIT n)
 SELECT jsonb_build_object('items',coalesce(jsonb_agg(to_jsonb(visible) ORDER BY id),'[]'::jsonb),
  'next_cursor',CASE WHEN (SELECT count(*) FROM candidate)>n THEN max(id) END) INTO page FROM visible;
 RETURN page;
END $read$;

CREATE OR REPLACE FUNCTION zasp_authorization80.studio_save(o text,w text,e text,a text,i text,k text,n bigint,d jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $save$
DECLARE op text:=CASE WHEN n=0 THEN 'createCustomSecurityAgent' ELSE 'updateCustomSecurityAgent' END;
 p jsonb; previous public.zasp_custom_security_agent_revisions%ROWTYPE; latest bigint; policy jsonb; allowed_pin boolean;
BEGIN
 p:=zasp_authorization80.product_request(o,w,e,a,op,'manage_workflows','environment',e,false,true,true,true);
 IF n<>0 AND p#>>'{path_parameters,id}' IS DISTINCT FROM i THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='wrong Studio agent'; END IF;
 IF NOT coalesce(public.zasp_valid_product_id(i) AND n BETWEEN 0 AND 999999 AND k ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$' AND zasp_authorization80.studio_valid(d),false)
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid custom definition'; END IF;
 d:=jsonb_set(d,'{read_tools}',(SELECT jsonb_agg(t ORDER BY t) FROM jsonb_array_elements_text(d->'read_tools') t));
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,a,k)::text,3));
 SELECT * INTO previous FROM public.zasp_custom_security_agent_revisions r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.actor,r.request_key)=(o,w,e,a,k);
 IF FOUND THEN
  IF (n=0 OR i=previous.id) AND previous.revision=n+1 AND previous.definition=d THEN RETURN zasp_authorization80.studio_revision(o,w,e,previous.id,previous.revision); END IF;
  RETURN '"conflict"'::jsonb;
 END IF;
 IF d->>'model_pin'<>'' THEN
  IF NOT EXISTS(SELECT FROM public.zasp_environment_ai_controls env WHERE (env.organization_id,env.workspace_id,env.environment_id)=(o,w,e)) THEN RETURN '"unqualified"'::jsonb; END IF;
  policy:=zasp_authorization80.ai_env_snapshot(o,w,e);
  SELECT policy->>'effective_mode' IN ('privatelink_bedrock','privatelink_vertex') AND policy->>'tier3_security_agent_planner_enabled'='true'
    AND policy->>'allow_redacted_summaries'='true' AND policy->>'tier3_model_pin'=d->>'model_pin' AND (d->>'budget_nano_credits')::bigint BETWEEN 1 AND (policy->>'monthly_budget_nano_credits')::bigint
    AND EXISTS(SELECT FROM public.model_qualifications q WHERE (q.organization_id,q.workspace_id,q.environment_id,q.provider,q.model,q.purpose)=(o,w,e,policy->>'effective_mode',d->>'model_pin','security_agent_triage')
      AND q.qualified AND q.checked_at<=now() AND q.expires_at>now() AND q.deployment_digest IS NOT NULL) INTO allowed_pin;
  IF allowed_pin IS DISTINCT FROM true THEN RETURN '"unqualified"'::jsonb; END IF;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(jsonb_build_array(o,w,e,i)::text,4));
 SELECT max(revision) INTO latest FROM public.zasp_custom_security_agent_revisions r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.id)=(o,w,e,i);
 IF latest IS NULL AND n<>0 THEN RETURN 'null'::jsonb; END IF;
 IF coalesce(latest,0)<>n THEN RETURN '"conflict"'::jsonb; END IF;
 INSERT INTO public.zasp_custom_security_agent_revisions(organization_id,workspace_id,environment_id,id,revision,definition,actor,request_key) VALUES(o,w,e,i,n+1,d,a,k);
 PERFORM zasp_authorization80.product_settled(p);
 RETURN zasp_authorization80.studio_revision(o,w,e,i,n+1);
END $save$;

DO $grants$ DECLARE f regprocedure; BEGIN
 FOREACH f IN ARRAY ARRAY['zasp_authorization80.studio_revision(text,text,text,text,bigint)'::regprocedure,'zasp_authorization80.studio_valid(jsonb)'::regprocedure,
 'zasp_authorization80.studio_read(text,text,text,text,text,integer)'::regprocedure,'zasp_authorization80.studio_save(text,text,text,text,text,text,bigint,jsonb)'::regprocedure] LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',f);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f);
  IF f::text LIKE '%studio_read(%' OR f::text LIKE '%studio_save(%' THEN EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO zasp_discovery_api',f); END IF;
 END LOOP;
END $grants$;
