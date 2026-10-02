-- Delivery can wake an existing owner, never create an execution or send IO.
CREATE TABLE zasp_temporal74.delivery_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 test_run_id text NOT NULL,effect_key text NOT NULL,message jsonb NOT NULL,message_digest bytea NOT NULL CHECK(octet_length(message_digest)=32),
 workflow_id text NOT NULL,accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,test_run_id),
 FOREIGN KEY(effect_key) REFERENCES zasp_temporal74.effects(effect_key));
ALTER TABLE zasp_temporal74.delivery_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal74.delivery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal74.delivery_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal74.delivery_receipts USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal74.delivery_receipts FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal74.delivery_identity(m jsonb) RETURNS zasp_temporal74.run_owners LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $identity$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;c public.zasp_red_team_runs%ROWTYPE;l public.zasp_security_agent_test_links%ROWTYPE;k text;start_value jsonb;
BEGIN
 IF NOT zasp_temporal74.current_ready() OR NOT public.zasp_red_team_principal_ready('zasp_red_team_worker') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test delivery principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(m,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_id','definition_version','input_digest']) OR octet_length(m::text)>4096 OR jsonb_typeof(m->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(m->>'definition_version'~'^[1-9][0-9]{0,6}$' AND (m->>'definition_version')::bigint<=1000000 AND m->>'input_digest'~'^[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test delivery message rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','definition_id'] LOOP IF jsonb_typeof(m->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(m->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test delivery scope rejected';END IF;END LOOP;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE (organization_id,workspace_id,environment_id,test_run_id)=(m->>'organization_id',m->>'workspace_id',m->>'environment_id',m->>'run_id');
 IF x.run_id IS NULL THEN
  IF EXISTS(SELECT 1 FROM zasp_temporal74.run_owners WHERE test_run_id=m->>'run_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test delivery scope unavailable';END IF;
  RETURN x;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1);
 SELECT * INTO c FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id);
 SELECT * INTO l FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id);
 start_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 PERFORM zasp_temporal74.start_identity(start_value);
 IF f.run_id IS NULL OR c.run_id IS NULL OR l.run_id IS NULL OR x.step_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_step',x.run_id||chr(31)||'0')
  OR x.test_run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_test_run',x.run_id||chr(31)||x.step_id||chr(31)||x.action_key)
  OR (f.action_key,l.action_key,l.input_digest,l.test_definition_id,l.test_definition_version) IS DISTINCT FROM(x.action_key,x.action_key,f.input_digest,c.definition_id,c.definition_version)
  OR f.effect_key IS DISTINCT FROM zasp_temporal74.effect_identity(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1)
  OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') OR f.snapshot->'targets'->>'test_run_id' IS DISTINCT FROM x.test_run_id OR f.snapshot->'targets'->>'input_digest' IS DISTINCT FROM encode(c.input_digest,'hex')
  OR m IS DISTINCT FROM jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',c.run_id,'definition_id',c.definition_id,'definition_version',c.definition_version,'input_digest',encode(c.input_digest,'hex'))
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal74.start_deliveries WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AND accepted_at IS NOT NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_red_team_outbox WHERE (organization_id,workspace_id,environment_id,outbox_id,deterministic_key,payload,payload_digest)=(x.organization_id,x.workspace_id,x.environment_id,public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'red_team_outbox',c.run_id),'test-jobs:'||c.run_id,m,digest(convert_to(m::text,'UTF8'),'sha256')))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,f.input_digest) AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test delivery identity changed';END IF;
 RETURN x;
END $identity$;

CREATE FUNCTION zasp_temporal74.delivery_message(o text,w text,e text,r text) RETURNS jsonb LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $message$
 SELECT b.payload FROM zasp_temporal74.run_owners x JOIN public.zasp_red_team_outbox b ON(b.organization_id,b.workspace_id,b.environment_id,b.outbox_id)=(x.organization_id,x.workspace_id,x.environment_id,public.zasp_discovery_canonical_id(o,w,e,'red_team_outbox',x.test_run_id)) WHERE(x.organization_id,x.workspace_id,x.environment_id,x.run_id)=(o,w,e,r)
$message$;

CREATE FUNCTION zasp_temporal74.delivery_parent_binding(m jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $binding$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;p jsonb;
BEGIN
 x:=zasp_temporal74.delivery_identity(m);IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test delivery parent owner absent';END IF;
 SELECT receipt INTO p FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);
 IF p IS NULL THEN
  SELECT jsonb_build_object('state',proof->'parent_state','reason',proof->'parent_reason') INTO p FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) AND proof->>'kind'='admitted' AND proof->>'effect_state'='reserved';
 END IF;
 IF p IS NULL OR p->>'state' IS NULL OR p->>'reason' IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test delivery parent proof absent';END IF;
 RETURN jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'state',p->'state','reason',p->'reason');
END $binding$;

-- No parent body leaves this lock-only role, and no caller terminal fields
-- determine the predicate. The private binding reauthenticates the message.
CREATE FUNCTION zasp_temporal74.delivery_parent_matches(m jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $parent$
DECLARE b jsonb;matched boolean;
BEGIN
 b:=zasp_temporal74.delivery_parent_binding(m);
 SELECT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,state,last_error_code)=(b->>'organization_id',b->>'workspace_id',b->>'environment_id',b->>'run_id',b->>'state',b->>'reason') AND completed_at IS NOT NULL AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL) INTO matched;
 IF b IS DISTINCT FROM zasp_temporal74.delivery_parent_binding(m) THEN RETURN false;END IF;
 RETURN matched;
END $parent$;

CREATE FUNCTION zasp_temporal74.delivery(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $delivery$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;d zasp_temporal74.delivery_receipts%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;t zasp_temporal74.stops%ROWTYPE;m jsonb:=q->'message';terminal_value boolean:=false;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='single-test delivery requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['operation','message']) OR octet_length(q::text)>8192 OR NOT COALESCE(q->>'operation' IN('read','accept'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='single-test delivery request rejected';END IF;
 x:=zasp_temporal74.delivery_identity(m);
 IF x.run_id IS NULL THEN
  IF q->>'operation'<>'read' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='single-test unowned acceptance rejected';END IF;
  RETURN jsonb_build_object('owned',false);
 END IF;
 SELECT * INTO STRICT f FROM zasp_temporal74.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1);
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)) THEN
  PERFORM zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);terminal_value:=NOT zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 ELSE
  SELECT * INTO t FROM zasp_temporal74.stops WHERE (organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
  IF t.run_id IS NOT NULL AND t.proof->>'kind'='admitted' AND t.proof->>'effect_state'='reserved' THEN
   PERFORM zasp_temporal74.stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   IF f.state IS DISTINCT FROM 'stopped' OR f.started_at IS NOT NULL OR zasp_temporal74.unresolved(x.organization_id,x.workspace_id,x.environment_id,x.run_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test unsent delivery proof changed';END IF;
   terminal_value:=true;
  END IF;
 END IF;
 SELECT * INTO d FROM zasp_temporal74.delivery_receipts WHERE (organization_id,workspace_id,environment_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id);
 IF d.run_id IS NULL AND q->>'operation'='accept' THEN
  INSERT INTO zasp_temporal74.delivery_receipts(organization_id,workspace_id,environment_id,run_id,test_run_id,effect_key,message,message_digest,workflow_id) VALUES(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.test_run_id,f.effect_key,m,digest(convert_to(m::text,'UTF8'),'sha256'),x.workflow_id) RETURNING * INTO d;
 END IF;
 IF d.run_id IS NOT NULL AND (d.run_id,d.effect_key,d.message,d.message_digest,d.workflow_id) IS DISTINCT FROM(x.run_id,f.effect_key,m,digest(convert_to(m::text,'UTF8'),'sha256'),x.workflow_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='single-test delivery receipt changed';END IF;
 RETURN jsonb_build_object('owned',true,'start',jsonb_build_object('ref',jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id),'definition_version',x.definition_version,'input_digest',x.input_digest),'terminal',terminal_value,'effect_key',f.effect_key,'delivery_digest',encode(digest(convert_to(m::text,'UTF8'),'sha256'),'hex'),'accepted_at',CASE WHEN d.accepted_at IS NULL THEN NULL ELSE to_char(d.accepted_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') END);
END $delivery$;

CREATE FUNCTION zasp_temporal74.delivery_ready(c text,f text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT zasp_temporal74.ready(c,f) AND public.zasp_red_team_principal_ready('zasp_red_team_worker')
$ready$;
