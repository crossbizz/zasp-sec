-- Product intent, not an orchestration lease. A generation is fixed by the
-- immutable ordered plan; a retry cannot mint another generation or send.
CREATE TABLE zasp_temporal68.effects(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 generation bigint NOT NULL CHECK(generation=1),effect_key text NOT NULL UNIQUE CHECK(effect_key~'^[a-f0-9]{64}$'),
 action_key text NOT NULL CHECK(action_key IN('create_temporary_policy','run_test')),input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=262144),snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),
 state text NOT NULL CHECK(state IN('reserved','started','unknown','verified','stopped','cleanup_pending','cleaned')),
 started_at timestamptz,completed_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id));
ALTER TABLE zasp_temporal68.effects OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.effects FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.effects USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

CREATE FUNCTION zasp_temporal68.effect_identity(o text,w text,e text,r text,s text,g bigint) RETURNS text LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT encode(digest(convert_to(concat_ws(chr(31),'zasp-temporal-effect-v1',o,w,e,r,s,g::text),'UTF8'),'sha256'),'hex')
$identity$;

CREATE FUNCTION zasp_temporal68.effect(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $effect$
DECLARE o text;w text;e text;r text;s text;op text;k text;g bigint;permit boolean:=false;live_value boolean;targets jsonb;snapshot_value jsonb;
 f zasp_temporal68.effects%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;b public.zasp_security_agent_run_budgets%ROWTYPE;device record;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor effect requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor catalog unavailable';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload'])
  OR octet_length(q::text)>4096 OR q->'generation' IS DISTINCT FROM '1'::jsonb OR q->'payload' IS DISTINCT FROM '{}'::jsonb
  OR NOT COALESCE(q->>'operation' IN('reserve','start','unknown','read'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor effect request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor effect scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';g:=1;op:=q->>'operation';live_value:=op IN('reserve','start');
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT live_value AND zasp_temporal68.principal_ready('zasp_temporal_compensation'))
  OR NOT zasp_temporal66.is_temporal(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor effect authority rejected';END IF;
 -- Use the existing Organization/budget/run/step/device order, with NOWAIT
 -- on independently owned deployment resources. No external IO is in here.
 PERFORM zasp_sa_multistep_prior.application_lock(o,w,e,r);
 PERFORM zasp_temporal68.current_plan(o,w,e,r,live_value);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO b FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND OR st.step_index NOT IN(0,1) OR st.action_key IS DISTINCT FROM (CASE st.step_index WHEN 0 THEN 'create_temporary_policy' ELSE 'run_test' END)
  OR rr.lease_token IS NOT NULL OR rr.lease_owner IS NOT NULL OR rr.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor effect step absent';END IF;
 IF live_value THEN
  IF st.step_index=0 THEN PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
  ELSE PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);END IF;
 END IF;
 SELECT * INTO f FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,g) FOR UPDATE;
 IF NOT FOUND THEN
  IF op<>'reserve' OR st.state<>'authorized' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))
   OR (SELECT count(*) FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))<>st.step_index
   OR st.step_index>=b.max_steps THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor effect reservation unavailable';END IF;
  INSERT INTO public.zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) VALUES(o,w,e,r,s,st.action_key,st.input_digest);
  INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,attempt) VALUES(o,w,e,r,s,st.action_key,st.input_digest,'pending',1);
  IF st.step_index=0 THEN
   SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',d.id,'credential_id',c.id) ORDER BY d.id),'[]'::jsonb) INTO targets FROM public.zasp_gateway_devices d JOIN LATERAL(SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d.id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1)c ON true WHERE (d.organization_id,d.workspace_id,d.environment_id,d.state)=(o,w,e,'active');
   IF jsonb_array_length(targets) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor gateway target bound rejected';END IF;
   FOR device IN SELECT * FROM jsonb_to_recordset(targets) AS t(device_id text,credential_id text) LOOP
    INSERT INTO public.zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version) VALUES(o,w,e,r,s,'apply',device.device_id,device.credential_id,1,1);
   END LOOP;
   SELECT jsonb_agg(jsonb_build_object('device_id',device_id,'credential_id',credential_id,'sequence',sequence,'policy_version',policy_version) ORDER BY device_id) INTO targets FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
  ELSE
   targets:=zasp_temporal68.test_reserve(o,w,e,r,s);
  END IF;
  snapshot_value:=jsonb_build_object('plan_hash',encode(rr.plan_hash,'hex'),'input_digest',encode(st.input_digest,'hex'),'targets',targets);
  INSERT INTO zasp_temporal68.effects VALUES(o,w,e,r,s,g,zasp_temporal68.effect_identity(o,w,e,r,s,g),st.action_key,st.input_digest,rr.plan_hash,snapshot_value,digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'reserved',NULL,NULL) RETURNING * INTO f;
  UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 END IF;
 IF f.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(o,w,e,r,s,g) OR (f.input_digest,f.plan_hash,f.action_key) IS DISTINCT FROM(st.input_digest,rr.plan_hash,st.action_key)
  OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') OR f.snapshot->>'plan_hash' IS DISTINCT FROM encode(rr.plan_hash,'hex') OR f.snapshot->>'input_digest' IS DISTINCT FROM encode(st.input_digest,'hex')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,x.input_digest)=(o,w,e,r,s,f.action_key,f.input_digest) AND x.lease_token IS NULL AND x.lease_owner IS NULL AND x.lease_expires_at IS NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,x.input_digest)=(o,w,e,r,s,f.action_key,f.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor effect intent changed';END IF;
 IF op='start' AND f.state='reserved' THEN
  UPDATE zasp_temporal68.effects SET state='started',started_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,g) RETURNING * INTO f;
  UPDATE public.zasp_security_agent_effects SET state='unknown_outcome',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  permit:=true;
 ELSIF op='unknown' THEN
  IF f.state NOT IN('started','unknown') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor effect not sent';END IF;
  UPDATE zasp_temporal68.effects SET state='unknown' WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,g) RETURNING * INTO f;
 END IF;
 IF live_value THEN
  IF st.step_index=0 THEN PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);ELSE PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);END IF;
 END IF;
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor effect catalog changed';END IF;
 RETURN to_jsonb(f)||jsonb_build_object('send_permit',permit);
END $effect$;
