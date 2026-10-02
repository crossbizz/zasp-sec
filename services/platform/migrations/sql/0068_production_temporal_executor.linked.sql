-- The child remains lease-free. Its durable link excludes generic red-team
-- claims; only this parent's authenticated effect can prepare or dispatch it.
CREATE TABLE zasp_temporal68.test_inputs(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,test_run_id text NOT NULL,
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object' AND octet_length(manifest::text)<=16384),
 body bytea NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 65536),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,test_run_id));
ALTER TABLE zasp_temporal68.test_inputs OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.test_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.test_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.test_inputs USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.test_inputs FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

-- Keep the full endpoint, credential binding, winning observation, complete
-- snapshot and source-evidence comparison. The caller owns authentication.
DO $target$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_invocation_target(text,text,text,text,text,text,bigint)'::regprocedure);
 d:=replace(d,'FUNCTION public.zasp_production_security_agent_existing_tests_invocation_target(', 'FUNCTION zasp_temporal68.test_target(');
 needle:='NOT COALESCE(zasp_red_team_principal_ready(''zasp_red_team_adapter'') OR zasp_red_team_principal_ready(''zasp_red_team_worker''),false) OR ';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'executor target predecessor rejected';END IF;
 EXECUTE replace(d,needle,'');
END $target$;

CREATE FUNCTION zasp_temporal68.test_reserve(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $reserve$
DECLARE child text;item jsonb;resolution jsonb;input_hash bytea;d public.zasp_red_team_definitions%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;actor text;
BEGIN
 SELECT plan->'steps'->1 INTO STRICT item FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,state)=(o,w,e,r,s,1,'run_test','authorized');
 SELECT requested_by INTO STRICT actor FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO d FROM public.zasp_red_team_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,target_id,target_kind,enabled)=(o,w,e,item->>'target_id',(item->>'test_definition_version')::bigint,item->>'test_target_id',item->>'test_target_kind',true);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked definition changed';END IF;
 resolution:=zasp_temporal68.test_target(o,w,e,d.target_id,d.target_kind,d.definition_id,d.version);
 child:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_run',r||chr(31)||s||chr(31)||'run_test');
 input_hash:=digest(convert_to(jsonb_build_object('definition_id',d.definition_id,'definition_version',d.version,'run_id',child)::text,'UTF8'),'sha256');
 INSERT INTO public.zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,input_digest) VALUES(o,w,e,child,d.definition_id,d.version,actor,input_hash);
 INSERT INTO public.zasp_security_agent_test_links(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,test_definition_id,test_definition_version,test_run_id,target_id,target_kind,test_categories,result)
  VALUES(o,w,e,r,s,'run_test',st.input_digest,d.definition_id,d.version,child,d.target_id,d.target_kind,d.categories,jsonb_build_object('test_run_id',child,'definition_id',d.definition_id,'definition_version',d.version,'state','pending','replayed',false));
 RETURN jsonb_build_object('step',item,'test_run_id',child,'input_digest',encode(input_hash,'hex'),'resolution',resolution);
END $reserve$;

CREATE FUNCTION zasp_temporal68.linked(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $linked$
DECLARE o text;w text;e text;r text;s text;op text;intent jsonb;p jsonb;doc jsonb;bytes bytea;resolution jsonb;permit boolean:=false;
 link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;prepared zasp_temporal68.test_inputs%ROWTYPE;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor linked principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>131072
  OR NOT COALESCE(q->>'operation' IN('read','input','dispatch'),false) OR jsonb_typeof(q->'payload') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor linked request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';op:=q->>'operation';p:=q->'payload';
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);
 IF intent->>'action_key' IS DISTINCT FROM 'run_test' OR intent->>'state' NOT IN('reserved','started','unknown') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked intent unavailable';END IF;
 SELECT * INTO link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,link.test_run_id) FOR UPDATE NOWAIT;
 IF child.run_id IS NULL OR child.state<>'queued' OR child.cancel_requested OR child.lease_token IS NOT NULL OR child.worker_id IS NOT NULL OR child.lease_expires_at IS NOT NULL
  OR (link.test_definition_id,link.test_definition_version,link.input_digest,link.action_key) IS DISTINCT FROM(child.definition_id,child.definition_version,decode(intent->'snapshot'->>'input_digest','hex'),'run_test'::text)
  OR child.run_id IS DISTINCT FROM intent->'snapshot'->'targets'->>'test_run_id' OR encode(child.input_digest,'hex') IS DISTINCT FROM intent->'snapshot'->'targets'->>'input_digest'
  OR link.reconcile_state<>'pending' OR link.reconcile_token IS NOT NULL OR link.reconcile_worker IS NOT NULL OR link.reconcile_expires_at IS NOT NULL OR link.reconcile_settlement IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked association changed';END IF;
 resolution:=zasp_temporal68.test_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version);
 IF resolution IS DISTINCT FROM intent->'snapshot'->'targets'->'resolution' OR link.test_categories IS DISTINCT FROM resolution->'comparison'->'categories' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked target changed';END IF;
 SELECT * INTO prepared FROM zasp_temporal68.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF op='input' THEN
  IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['manifest','body']) OR jsonb_typeof(p->'body') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor linked input rejected';END IF;
  bytes:=decode(p->>'body','base64');doc:=zasp_sa_multistep_prior.test_validate_input(o,w,e,r,s,p->'manifest',bytes);
  IF prepared.run_id IS NULL THEN
   IF intent->>'state'<>'reserved' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked input too late';END IF;
   INSERT INTO zasp_temporal68.test_inputs VALUES(o,w,e,r,s,child.run_id,p->'manifest',bytes) RETURNING * INTO prepared;
  ELSIF (prepared.manifest,prepared.body) IS DISTINCT FROM(p->'manifest',bytes) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked input replay changed';END IF;
 ELSIF p<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor linked unexpected payload';
 ELSIF op='dispatch' THEN
  IF prepared.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor linked input absent';END IF;
  PERFORM zasp_sa_multistep_prior.test_validate_input(o,w,e,r,s,prepared.manifest,prepared.body);
  intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','start','payload','{}'::jsonb));permit:=(intent->>'send_permit')::boolean;
 END IF;
 PERFORM zasp_sa_multistep_prior.test_current(o,w,e,r,s);
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor linked catalog changed';END IF;
 RETURN jsonb_build_object('effect_key',intent->>'effect_key','generation',1,'test_run_id',child.run_id,'input_digest',encode(child.input_digest,'hex'),'definition_id',child.definition_id,'definition_version',child.definition_version,'target_id',link.target_id,'target_kind',link.target_kind,'categories',link.test_categories,'target_resolution',resolution,'input_manifest',prepared.manifest,'input_body',convert_from(prepared.body,'UTF8'),'send_permit',permit);
END $linked$;

CREATE TABLE zasp_temporal68.invocations(LIKE public.zasp_security_agent_test_invocations INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE zasp_temporal68.invocations DROP COLUMN lease_digest,ADD effect_key text NOT NULL,
 ADD PRIMARY KEY(organization_id,workspace_id,environment_id,test_run_id,category),ADD CHECK(attempt=1),
 ADD FOREIGN KEY(effect_key) REFERENCES zasp_temporal68.effects(effect_key),
 ADD FOREIGN KEY(organization_id,workspace_id,environment_id,test_run_id) REFERENCES zasp_temporal68.test_inputs(organization_id,workspace_id,environment_id,test_run_id);
ALTER TABLE zasp_temporal68.invocations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.invocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.invocations FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.invocations USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

CREATE FUNCTION zasp_temporal68.adapter_ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 BEGIN RETURN zasp_temporal68.ready(c,f) AND zasp_temporal68.adapter_principal_ready();END
$ready$;

-- Adapter and terminal readers cannot use the executor-granted effect entry.
-- They still bind its saved intent to the same public plan, step and child.
CREATE FUNCTION zasp_temporal68.test_intent_valid(o text,w text,e text,r text,s text) RETURNS boolean LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $valid$
 SELECT EXISTS(
  SELECT 1 FROM zasp_temporal68.effects f
  JOIN public.zasp_security_agent_runs rr USING(organization_id,workspace_id,environment_id,run_id)
  JOIN public.zasp_security_agent_steps st USING(organization_id,workspace_id,environment_id,run_id,step_id)
  JOIN public.zasp_security_agent_effects fx USING(organization_id,workspace_id,environment_id,run_id,step_id)
  JOIN public.zasp_security_agent_step_reservations sr USING(organization_id,workspace_id,environment_id,run_id,step_id)
  JOIN public.zasp_security_agent_test_links l USING(organization_id,workspace_id,environment_id,run_id,step_id)
  JOIN public.zasp_red_team_runs c ON(c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(o,w,e,l.test_run_id)
  WHERE(f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.generation,f.action_key)=(o,w,e,r,s,1,'run_test')
   AND s=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'1')
   AND c.run_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_test_run',r||chr(31)||s||chr(31)||'run_test')
   AND f.effect_key=zasp_temporal68.effect_identity(o,w,e,r,s,1) AND st.step_index=1
   AND (st.action_key,fx.action_key,sr.action_key,l.action_key)=('run_test','run_test','run_test','run_test')
   AND (st.input_digest,fx.input_digest,sr.input_digest,l.input_digest)=(f.input_digest,f.input_digest,f.input_digest,f.input_digest)
   AND f.plan_hash=rr.plan_hash AND f.snapshot->>'plan_hash'=encode(rr.plan_hash,'hex') AND f.snapshot->>'input_digest'=encode(f.input_digest,'hex')
   AND f.snapshot_digest=digest(convert_to(f.snapshot::text,'UTF8'),'sha256')
   AND f.snapshot->'targets'->>'test_run_id'=c.run_id AND f.snapshot->'targets'->>'input_digest'=encode(c.input_digest,'hex')
   AND (l.test_definition_id,l.test_definition_version)=(c.definition_id,c.definition_version)
   AND rr.lease_owner IS NULL AND rr.lease_token IS NULL AND rr.lease_expires_at IS NULL
   AND fx.lease_owner IS NULL AND fx.lease_token IS NULL AND fx.lease_expires_at IS NULL
   AND c.worker_id IS NULL AND c.lease_token IS NULL AND c.lease_expires_at IS NULL)
$valid$;

CREATE FUNCTION zasp_temporal68.invocation(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $invocation$
DECLARE o text;w text;e text;child_id text;op text;k text;category_value text;key_value text;payload jsonb;resolution jsonb;request_hash bytea;curated text;result_value jsonb;new_start boolean:=false;
 link public.zasp_security_agent_test_links%ROWTYPE;child public.zasp_red_team_runs%ROWTYPE;f zasp_temporal68.effects%ROWTYPE;j zasp_temporal68.invocations%ROWTYPE;prepared zasp_temporal68.test_inputs%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='executor invocation requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.adapter_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor invocation principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','effect_key','operation','payload','checksum','fingerprint']) OR octet_length(q::text)>8192
  OR NOT COALESCE(q->>'operation' IN('resolve','start','complete') AND q->>'effect_key'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor invocation request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor invocation scope rejected';END IF;
 END LOOP;
 IF NOT COALESCE(zasp_temporal68.adapter_ready(q->>'checksum',q->>'fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor invocation version rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';child_id:=q->>'run_id';op:=q->>'operation';key_value:=q->>'effect_key';payload:=q->'payload';category_value:=payload->>'category';
 IF NOT zasp_sa_multistep_prior.closed(payload,CASE op WHEN 'resolve' THEN ARRAY['category','target_id','target_kind'] WHEN 'start' THEN ARRAY['category','request_digest'] ELSE ARRAY['category','request_digest','http_status','response_digest','protected','credential_version_digest'] END)
  OR NOT COALESCE(category_value IN('prompt_injection','tool_abuse','data_leakage','authorization_bypass','excessive_agency','sensitive_information'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor invocation payload rejected';END IF;
 SELECT * INTO link FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,test_run_id)=(o,w,e,child_id);
 IF NOT FOUND OR NOT zasp_temporal66.is_temporal(o,w,e,link.run_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor invocation owner rejected';END IF;
 PERFORM zasp_sa_multistep_prior.test_lock(o,w,e,link.run_id);
 PERFORM zasp_temporal68.current_plan(o,w,e,link.run_id,false);
 SELECT * INTO f FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key,action_key)=(o,w,e,link.run_id,link.step_id,1,key_value,'run_test') FOR UPDATE;
 SELECT * INTO child FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,child_id) FOR UPDATE NOWAIT;
 SELECT * INTO prepared FROM zasp_temporal68.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(o,w,e,link.run_id,link.step_id,child_id);
 IF NOT zasp_temporal68.test_intent_valid(o,w,e,link.run_id,link.step_id) OR f.run_id IS NULL OR prepared.run_id IS NULL OR child.run_id IS NULL OR f.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(o,w,e,link.run_id,link.step_id,1)
  OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') OR f.snapshot->'targets'->>'test_run_id' IS DISTINCT FROM child_id
  OR f.snapshot->'targets'->>'input_digest' IS DISTINCT FROM encode(child.input_digest,'hex') OR f.input_digest IS DISTINCT FROM link.input_digest
  OR (link.test_definition_id,link.test_definition_version) IS DISTINCT FROM(child.definition_id,child.definition_version)
  OR NOT link.test_categories ? category_value OR link.test_categories IS DISTINCT FROM f.snapshot->'targets'->'resolution'->'comparison'->'categories'
  OR child.worker_id IS NOT NULL OR child.lease_token IS NOT NULL OR child.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor invocation association changed';END IF;
 PERFORM zasp_sa_multistep_prior.test_validate_input(o,w,e,link.run_id,link.step_id,prepared.manifest,prepared.body);
 resolution:=f.snapshot->'targets'->'resolution';
 IF op<>'complete' THEN
  PERFORM zasp_sa_multistep_prior.test_current(o,w,e,link.run_id,link.step_id);
  IF child.state<>'queued' OR child.cancel_requested OR link.reconcile_state<>'pending' OR f.state NOT IN('started','unknown')
   OR resolution IS DISTINCT FROM zasp_temporal68.test_target(o,w,e,link.target_id,link.target_kind,link.test_definition_id,link.test_definition_version) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor invocation current authority changed';END IF;
 END IF;
 IF op='resolve' THEN
  IF (payload->>'target_id',payload->>'target_kind') IS DISTINCT FROM(link.target_id,link.target_kind) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor invocation target rejected';END IF;
  result_value:=resolution->'binding';
 ELSE
  IF NOT COALESCE(payload->>'request_digest'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor invocation digest rejected';END IF;
  request_hash:=decode(payload->>'request_digest','hex');
  curated:='{"schema_version":"red-team-target-v1","run_id":"'||child_id||'","target_id":"'||link.target_id||'","target_kind":"'||link.target_kind||'","category":"'||category_value||'","input":'||to_json(zasp_sa_multistep_prior.test_prompt(category_value))::text||'}';
  IF request_hash IS DISTINCT FROM digest(convert_to(curated,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor curated invocation rejected';END IF;
  SELECT * INTO j FROM zasp_temporal68.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,child_id,category_value) FOR UPDATE;
  IF j.test_run_id IS NOT NULL AND (j.effect_key,j.input_digest,j.request_digest,j.target_resolution) IS DISTINCT FROM(key_value,child.input_digest,request_hash,resolution) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor invocation replay conflict';END IF;
  IF op='start' AND j.state IS DISTINCT FROM 'completed' THEN
   IF f.state<>'started' OR EXISTS(SELECT 1 FROM zasp_temporal68.invocations WHERE (organization_id,workspace_id,environment_id,test_run_id,state)=(o,w,e,child_id,'started')) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor invocation outcome unknown';END IF;
   INSERT INTO zasp_temporal68.invocations(organization_id,workspace_id,environment_id,test_run_id,attempt,category,input_digest,request_digest,target_resolution,state,effect_key) VALUES(o,w,e,child_id,1,category_value,child.input_digest,request_hash,resolution,'started',key_value) RETURNING * INTO j;
   new_start:=true;
  ELSIF op='complete' THEN
   IF j.test_run_id IS NULL OR NOT COALESCE(payload->>'response_digest'~'^[a-f0-9]{64}$' AND payload->>'credential_version_digest'~'^[a-f0-9]{64}$' AND payload->>'credential_version_digest'<>repeat('0',64)
    AND jsonb_typeof(payload->'http_status')='number' AND payload->>'http_status'~'^[2-5][0-9]{2}$' AND (payload->'http_status'='200'::jsonb AND jsonb_typeof(payload->'protected')='boolean' OR payload->'http_status'<>'200'::jsonb AND payload->'protected'='null'::jsonb),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor invocation observation rejected';END IF;
   IF j.state='completed' THEN
    IF (j.http_status,j.response_digest,j.protected,j.credential_version_digest) IS DISTINCT FROM((payload->>'http_status')::integer,decode(payload->>'response_digest','hex'),(payload->>'protected')::boolean,decode(payload->>'credential_version_digest','hex')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor observation replay conflict';END IF;
   ELSE
    UPDATE zasp_temporal68.invocations SET state='completed',completed_at=clock_timestamp(),http_status=(payload->>'http_status')::integer,response_digest=decode(payload->>'response_digest','hex'),protected=(payload->>'protected')::boolean,credential_version_digest=decode(payload->>'credential_version_digest','hex') WHERE (organization_id,workspace_id,environment_id,test_run_id,category)=(o,w,e,child_id,category_value) RETURNING * INTO j;
   END IF;
  END IF;
  result_value:=jsonb_build_object('state',j.state,'attempt',1,'category',category_value,'input_digest',encode(j.input_digest,'hex'),'request_digest',encode(j.request_digest,'hex'),'target_binding',j.target_resolution->'binding','target_provenance',j.target_resolution->'provenance','target_comparison',j.target_resolution->'comparison','effect_key',j.effect_key);
  IF j.state='completed' THEN result_value:=result_value||jsonb_build_object('run_id',child_id,'http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected,'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));END IF;
 END IF;
 IF op<>'complete' THEN PERFORM zasp_sa_multistep_prior.test_current(o,w,e,link.run_id,link.step_id);END IF;
 IF NOT zasp_temporal68.current_ready() OR NOT zasp_temporal68.adapter_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor invocation authority changed';END IF;
 RETURN result_value;
END $invocation$;

CREATE FUNCTION zasp_temporal68.standalone_resolve(o text,w text,e text,target_value text,kind text,r text,lease_value text,category text,c text,f text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $standalone$
DECLARE result_value jsonb;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF current_setting('transaction_isolation')<>'read committed' OR NOT COALESCE(zasp_temporal68.adapter_ready(c,f),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor standalone adapter unavailable';END IF;
 result_value:=public.zasp_red_team_resolve_invocation(o,w,e,target_value,kind,r,lease_value,category);
 IF NOT COALESCE(zasp_temporal68.adapter_ready(c,f),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor standalone authority changed';END IF;
 RETURN result_value;
END $standalone$;
