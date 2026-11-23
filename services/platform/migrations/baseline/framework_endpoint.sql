-- Versioned, environment-scoped pre-tool templates. Editing a template does not
-- install a policy or grant authority to sign for any device.
CREATE TABLE IF NOT EXISTS public.zasp_pretool_cohort_policies (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 cohort text NOT NULL CHECK(cohort ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
 revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 1000000),
 settings jsonb NOT NULL, actor text NOT NULL, request_key text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY (organization_id, workspace_id, environment_id, cohort, revision),
 UNIQUE (organization_id, workspace_id, environment_id, cohort, actor, request_key)
);
ALTER TABLE public.zasp_pretool_cohort_policies OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_pretool_cohort_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_pretool_cohort_policies FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_pretool_cohort_policies FROM PUBLIC;
DO $policy_rls$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_policies WHERE schemaname='public' AND tablename='zasp_pretool_cohort_policies' AND policyname='pretool_authority') THEN
  CREATE POLICY pretool_authority ON public.zasp_pretool_cohort_policies TO zasp_discovery_authority USING(true) WITH CHECK(true);
 END IF;
END $policy_rls$;

CREATE OR REPLACE FUNCTION zasp_authorization80.pretool_cohort(o text,w text,e text,a text,op text,c text,k text,q jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $cohort$
DECLARE prior public.zasp_pretool_cohort_policies%ROWTYPE; rev bigint; settings_value jsonb;
 p jsonb; mut boolean:=op='updateEndpointPolicyCohort';
BEGIN
 IF op IS NULL OR op NOT IN('getEndpointPolicyCohort','updateEndpointPolicyCohort') OR c IS NULL OR c!~'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' THEN RAISE invalid_parameter_value; END IF;
 p:=zasp_authorization80.product_request(o,w,e,a,op,CASE WHEN mut THEN 'manage_workflows' ELSE 'view' END,'environment',e,false,true,mut,mut);
 IF p#>>'{path_parameters,cohort}' IS DISTINCT FROM c THEN RAISE insufficient_privilege; END IF;
 IF mut THEN
  IF k IS NULL OR length(k) NOT BETWEEN 8 AND 160 OR NOT COALESCE(jsonb_typeof(q)='object' AND q-ARRAY['expected_revision','mode','failure_mode','rules']='{}'::jsonb AND (q->>'expected_revision')::bigint BETWEEN 0 AND 999999 AND q->>'mode' IN ('monitor','enforce') AND q->>'failure_mode' IN ('open','closed') AND jsonb_typeof(q->'rules')='array' AND jsonb_array_length(q->'rules') BETWEEN 1 AND 32 AND octet_length(q::text)<32768,false) THEN RAISE invalid_parameter_value; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,'pretool',c),0));
  SELECT * INTO prior FROM public.zasp_pretool_cohort_policies WHERE (organization_id,workspace_id,environment_id,cohort,actor,request_key)=(o,w,e,c,a,k);
  IF FOUND THEN
   IF prior.settings IS DISTINCT FROM q-'expected_revision' OR prior.revision<>(q->>'expected_revision')::bigint+1 THEN RETURN '"conflict"'::jsonb; END IF;
   PERFORM zasp_authorization80.product_settled(p);
   RETURN prior.settings||jsonb_build_object('cohort',c,'revision',prior.revision);
  END IF;
 END IF;
 SELECT revision,settings INTO rev,settings_value FROM public.zasp_pretool_cohort_policies
 WHERE (organization_id,workspace_id,environment_id,cohort)=(o,w,e,c) ORDER BY revision DESC LIMIT 1;
 rev:=coalesce(rev,0);
 IF mut THEN
  IF rev<>(q->>'expected_revision')::bigint THEN RETURN '"conflict"'::jsonb; END IF;
  rev:=rev+1;settings_value:=q-'expected_revision';
  INSERT INTO public.zasp_pretool_cohort_policies(organization_id,workspace_id,environment_id,cohort,revision,settings,actor,request_key) VALUES(o,w,e,c,rev,settings_value,a,k);
 END IF;
 PERFORM zasp_authorization80.product_settled(p);
 RETURN coalesce(settings_value,'{"mode":"monitor","failure_mode":"open","rules":[]}'::jsonb)||jsonb_build_object('cohort',c,'revision',rev);
END $cohort$;
ALTER FUNCTION zasp_authorization80.pretool_cohort(text,text,text,text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_authorization80.pretool_cohort(text,text,text,text,text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_authorization80.pretool_cohort(text,text,text,text,text,text,text,jsonb) TO zasp_discovery_api;

-- Extend the established device/generation-fenced exchange. Both audiences use
-- the same registered keys, idempotency checks and row locks.
DO $install_pretool$
DECLARE f text; anchor text; updated text;
BEGIN
 SELECT pg_get_functiondef('zasp_authorization80.endpoint_admin(text,text,text,text,text,text,text,bigint,jsonb)'::regprocedure) INTO f;
 IF position('pretool_policy_template' IN f)=0 THEN
  anchor:='   UPDATE public.zasp_endpoint_devices SET policy_bundle=';
  updated:=replace(f,anchor,$body$
   IF q?'pretool_policy_template' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws('/',o,w,e,'pretool',d.cohort),0));
    IF q->'pretool_policy_template' IS DISTINCT FROM (SELECT settings FROM public.zasp_pretool_cohort_policies t
      WHERE (t.organization_id,t.workspace_id,t.environment_id,t.cohort)=(o,w,e,d.cohort) ORDER BY revision DESC LIMIT 1) THEN RETURN '"conflict"'::jsonb; END IF;
   END IF;
$body$||anchor);
  IF f=updated THEN RAISE EXCEPTION 'pretool publication anchor unavailable'; END IF;
  f:=updated;
  anchor:='     )||COALESCE((SELECT jsonb_build_object(''graph_evidence_id''';
  updated:=replace(f,anchor,$detail$     )||CASE WHEN r.observation->>'audience'='zasp.endpoint-observation.v2' THEN jsonb_strip_nulls(jsonb_build_object('adapter',r.observation->'adapter','tool_class',r.observation->'tool','rule_id',r.observation->'rule_id','reason_code',r.observation->'reason_code')) ELSE '{}'::jsonb END||COALESCE((SELECT jsonb_build_object('graph_evidence_id'$detail$);
  IF f=updated THEN RAISE EXCEPTION 'pretool device detail anchor unavailable'; END IF;
  EXECUTE updated;
 END IF;
 SELECT pg_get_functiondef('zasp_authorization80.endpoint_machine(text,text,text,text,text,text,bigint,text,jsonb)'::regprocedure) INTO f;
 IF position('zasp.endpoint-observation.v2' IN f)=0 THEN
  anchor:='''macos_claude_ticket'',''linux_claude_ticket_test'',''windows_inventory''';
  updated:=replace(f,anchor,anchor||',''macos_claude_pretool_v2'',''linux_claude_pretool_v2_test'',''macos_codex_pretool_v2'',''windows_claude_pretool_v2''');
  IF f=updated THEN RAISE EXCEPTION 'pretool heartbeat anchor unavailable'; END IF;
  f:=updated;
  anchor:='   IF NOT COALESCE(jsonb_typeof(rec)=''object'' AND (rec-ARRAY[''audience''';
  updated:=replace(f,anchor,$body$
   IF rec->>'audience'='zasp.endpoint-observation.v2' THEN
    IF NOT coalesce((rec-ARRAY['audience','binding','action_id','session_ref','observed_at','policy_revision','mode','adapter','tool','rule_id','reason_code','verdict','would_block','target_class','skill_usage','target_effect'])='{}'::jsonb
    AND rec->'binding'=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'device_id',target_id,'credential_generation',gen)
    AND rec->>'action_id'~'^[a-f0-9]{64}$' AND rec->>'session_ref'~'^[a-f0-9]{64}$'
    AND rec->>'adapter' IN ('macos_claude_pretool_v2','linux_claude_pretool_v2_test','macos_codex_pretool_v2','windows_claude_pretool_v2')
    AND rec->>'tool' IN('shell','mcp','file','web','other') AND rec->>'target_class'='unknown' AND rec->>'target_effect'='unknown' AND rec->>'skill_usage'='unknown'
    AND rec->>'mode' IN('','monitor','enforce') AND rec->>'verdict' IN('continue','deny','unavailable') AND jsonb_typeof(rec->'would_block')='boolean'
    AND (rec->>'policy_revision')::bigint BETWEEN 0 AND 9007199254740992 AND (rec->>'observed_at')::timestamptz<=clock_timestamp()+interval '30 seconds'
    AND (NOT rec?'rule_id' OR rec->>'rule_id'~'^[a-z][a-z0-9._-]{0,63}$') AND rec->>'reason_code' IN('within_scope','policy_expired','policy_unavailable','state_unavailable','input_unavailable','spool_full','mcp_tool_restricted','destination_restricted','shell_pipe','secret_transfer','reverse_shell','privileged_mode','encoded_execution','ssh','aws','gcloud','dotenv','pem','identity_key','unverifiable_path'),false) THEN RAISE invalid_parameter_value; END IF;
   ELSIF NOT COALESCE(jsonb_typeof(rec)='object' AND (rec-ARRAY['audience'$body$);
  IF f=updated THEN RAISE EXCEPTION 'pretool observations anchor unavailable'; END IF;
  EXECUTE updated;
 END IF;
END $install_pretool$;
