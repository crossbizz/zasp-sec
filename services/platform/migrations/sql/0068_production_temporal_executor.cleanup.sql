-- Compensation consumes an existing effect and its exact persisted sources.
-- It cannot reserve work, authorize a test, or restore requester permission.
CREATE TABLE zasp_temporal68.cleanups(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,generation bigint NOT NULL CHECK(generation=1),
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=262144),snapshot_digest bytea NOT NULL,
 state text NOT NULL CHECK(state IN('pending','unknown','cleaned')),version bigint NOT NULL DEFAULT 2,attempt integer NOT NULL DEFAULT 1,reason text NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,receipt jsonb,receipt_digest bytea,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation) REFERENCES zasp_temporal68.effects(organization_id,workspace_id,environment_id,run_id,step_id,generation));
ALTER TABLE zasp_temporal68.cleanups OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.cleanups ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.cleanups FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.cleanups USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

-- Renew removal authority without replacing either the original signed marker
-- or a prepared/stored/read delivery. A renewal never reserves a new effect.
CREATE TABLE zasp_temporal68.cleanup_renewals(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,device_id text NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),body jsonb NOT NULL CHECK(octet_length(body::text)<=32768),body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,device_id,revision),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal68.cleanups(organization_id,workspace_id,environment_id,run_id));
ALTER TABLE zasp_temporal68.cleanup_renewals OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.cleanup_renewals ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.cleanup_renewals FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.cleanup_renewals USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.cleanup_renewals FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal68.cleanup_marker(t public.zasp_security_agent_temporary_policy_targets) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $marker$
DECLARE x zasp_temporal68.cleanup_renewals%ROWTYPE;marker jsonb;prior_expiry timestamptz:=t.expires_at;revision_value bigint:=0;
BEGIN
 marker:=jsonb_build_object('issued_at',t.issued_at,'expires_at',t.expires_at);
 FOR x IN SELECT * FROM zasp_temporal68.cleanup_renewals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.device_id) ORDER BY revision LOOP
  IF x.revision<>revision_value+1 OR NOT zasp_sa_multistep_prior.closed(x.body,ARRAY['effect_key','source','envelope']) OR x.body_digest IS DISTINCT FROM digest(convert_to(x.body::text,'UTF8'),'sha256')
   OR x.body->'source' IS DISTINCT FROM to_jsonb(t)-ARRAY['state','verified_at']
  OR x.body->>'effect_key' IS DISTINCT FROM zasp_temporal68.effect_identity(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,1)
   OR NOT COALESCE((x.body->'envelope'->>'expires_at')::timestamptz=(x.body->'envelope'->>'issued_at')::timestamptz+interval '5 minutes',false)
   OR (x.body->'envelope'->>'issued_at')::timestamptz<prior_expiry
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,'temporal_cleanup_renewed')
    AND a.audit_id=public.zasp_discovery_canonical_id(t.organization_id,t.workspace_id,t.environment_id,'security_agent_temporal_cleanup_renewal',x.body->>'effect_key'||chr(31)||t.device_id||chr(31)||x.revision::text) AND a.correlation_id=a.audit_id AND a.body=x.body AND a.event_digest=x.body_digest) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup renewal evidence changed';END IF;
  marker:=x.body->'envelope';prior_expiry:=(marker->>'expires_at')::timestamptz;revision_value:=x.revision;
 END LOOP;
 RETURN marker;
END $marker$;

-- Keep a still-valid composition cap stable across marker-only retries. Once
-- it expires, a fresh signed renewal supplies a new bounded cap. No source
-- record or acknowledged bundle is rewritten to extend its lifetime.
CREATE FUNCTION zasp_temporal68.cleanup_cap(o text,w text,e text,r text,s text,d text) RETURNS timestamptz LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $cap$
DECLARE t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;cap_value timestamptz;
BEGIN
 SELECT * INTO STRICT t FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'cleanup',d) AND state IN('stored','verified');
 SELECT GREATEST(t.issued_at+interval '24 hours',(SELECT (composition->>'replacement_expires_at')::timestamptz FROM zasp_temporal68.deliveries WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,'cleanup',d))) INTO cap_value;
 IF cap_value<=clock_timestamp() THEN cap_value:=(zasp_temporal68.cleanup_marker(t)->>'issued_at')::timestamptz+interval '24 hours';END IF;
 RETURN cap_value;
END $cap$;
DO $composition$
DECLARE d text;needle text;
BEGIN
 d:=pg_get_functiondef('zasp_sa_multistep_prior.cleanup_composition(text,text,text,text,text,text)'::regprocedure);
 needle:='SELECT issued_at+interval ''24 hours'' INTO STRICT cap FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,''cleanup'',d) AND state IN(''stored'',''verified'');';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor cleanup composition predecessor changed';END IF;
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.cleanup_composition(','FUNCTION zasp_temporal68.cleanup_composition(');
 d:=replace(d,needle,'cap:=zasp_temporal68.cleanup_cap(o,w,e,r,s,d);');
 EXECUTE d;
END $composition$;

CREATE FUNCTION zasp_temporal68.cleanup_snapshot(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $snapshot$
DECLARE f zasp_temporal68.effects%ROWTYPE;targets jsonb;application jsonb;reservation jsonb;test_value jsonb;test_step text;
BEGIN
 PERFORM zasp_temporal68.current_plan(o,w,e,r,false);
 SELECT * INTO f FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
 SELECT jsonb_agg(to_jsonb(t) ORDER BY device_id) INTO targets FROM public.zasp_security_agent_temporary_policy_targets t WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
 SELECT to_jsonb(x) INTO application FROM public.zasp_sa_multistep_receipts x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT to_jsonb(x) INTO reservation FROM public.zasp_security_agent_step_reservations x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF f.action_key IS DISTINCT FROM 'create_temporary_policy' OR f.state NOT IN('started','unknown','cleanup_pending','cleaned') OR f.effect_key IS DISTINCT FROM zasp_temporal68.effect_identity(o,w,e,r,s,1)
  OR f.snapshot_digest IS DISTINCT FROM digest(convert_to(f.snapshot::text,'UTF8'),'sha256') OR reservation IS NULL OR targets IS NULL OR jsonb_array_length(targets) NOT BETWEEN 1 AND 100
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(targets) t WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(f.snapshot->'targets') x WHERE (x->>'device_id',x->>'credential_id',x->'sequence',x->'policy_version')=(t->>'device_id',t->>'credential_id',t->'sequence',t->'policy_version'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup effect evidence unavailable';END IF;
 SELECT step_id INTO test_step FROM zasp_temporal68.effects WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,'run_test');
 IF FOUND THEN test_value:=zasp_temporal68.test_terminal_evidence(o,w,e,r,test_step);END IF;
 IF application IS NOT NULL AND (application->>'receipt_kind'<>'temporary_policy_applied.v1' OR application->>'result_digest' IS DISTINCT FROM (SELECT to_jsonb(x)->>'result_digest' FROM public.zasp_security_agent_effects x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup application changed';END IF;
 RETURN jsonb_build_object('kind',CASE WHEN application IS NULL THEN 'partial' ELSE 'applied' END,'effect_key',f.effect_key,'intent',f.snapshot,'targets',targets,'application',application,'reservation',reservation,'test',test_value);
END $snapshot$;

CREATE FUNCTION zasp_temporal68.cleanup_current(o text,w text,e text,r text,s text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
DECLARE c zasp_temporal68.cleanups%ROWTYPE;marker_target public.zasp_security_agent_temporary_policy_targets%ROWTYPE;
BEGIN
 SELECT * INTO c FROM zasp_temporal68.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF c.run_id IS NULL OR c.state NOT IN('pending','unknown','cleaned') OR c.snapshot IS DISTINCT FROM zasp_temporal68.cleanup_snapshot(o,w,e,r,s) OR c.snapshot_digest IS DISTINCT FROM digest(convert_to(c.snapshot::text,'UTF8'),'sha256')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('cancelled','needs_human','failed','inconclusive','contained','remediated') AND completed_at IS NOT NULL)
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=(o,w,e,r,s,'cleanup') AND
   (NOT EXISTS(SELECT 1 FROM jsonb_array_elements(c.snapshot->'targets') x WHERE (x->>'device_id',x->>'credential_id')=(t.device_id,t.credential_id) AND x->>'state' IN('stored','verified'))
    OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,t.device_id,'active'))
    OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1)
    OR t.state<>'planned' AND (t.policies IS DISTINCT FROM '[]'::jsonb OR t.failure_mode<>'closed' OR t.expires_at<>t.issued_at+interval '5 minutes' OR t.desired_generation IS NULL))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup snapshot changed';END IF;
 FOR marker_target IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') LOOP
  PERFORM zasp_temporal68.cleanup_marker(marker_target);
 END LOOP;
END $current$;

CREATE FUNCTION zasp_temporal68.cleanup_acks(o text,w text,e text,r text,s text,live_value boolean) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $acks$
DECLARE t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;d zasp_temporal68.deliveries%ROWTYPE;b public.zasp_runtime_gateway_policy_bundles%ROWTYPE;v jsonb:='[]';composition_value jsonb;readback jsonb;
BEGIN
 IF (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup')) IS DISTINCT FROM (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') AND state IN('stored','verified')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup target set changed';END IF;
 FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') ORDER BY device_id LOOP
  PERFORM zasp_temporal68.cleanup_marker(t);
  PERFORM zasp_temporal68.delivery_history(t);
  SELECT * INTO d FROM zasp_temporal68.deliveries WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,'cleanup',t.device_id);
  SELECT * INTO b FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(o,w,e,t.device_id,d.sequence);
  readback:=zasp_sa_multistep_prior.cleanup_bundle_snapshot(b);
  IF d.state IS DISTINCT FROM 'acknowledged' OR d.read_at IS NULL OR d.acknowledged_at IS NULL OR d.envelope_digest IS DISTINCT FROM b.envelope_digest OR b.credential_id IS DISTINCT FROM t.credential_id OR (d.source_digest,d.source_sequence) IS DISTINCT FROM(t.envelope_digest,t.sequence) OR d.desired_generation<t.desired_generation
   OR (readback-ARRAY['issued_at','expires_at']) IS DISTINCT FROM(d.envelope-ARRAY['issued_at','expires_at']) OR (b.issued_at,b.expires_at) IS DISTINCT FROM((d.envelope->>'issued_at')::timestamptz,(d.envelope->>'expires_at')::timestamptz)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(d.composition->'temporary_sources') x WHERE (x->>'run_id',x->>'step_id')=(r,s))
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,'temporal_cleanup_delivery_finish')
    AND a.audit_id=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_delivery',zasp_temporal68.effect_identity(o,w,e,r,s,1)||chr(31)||'cleanup'||chr(31)||t.device_id||chr(31)||d.sequence::text) AND a.correlation_id=a.audit_id AND a.event_digest=digest(convert_to(to_jsonb(d)::text,'UTF8'),'sha256')
    AND a.body=jsonb_build_object('composition',d.composition,'request',jsonb_build_object('device_id',t.device_id,'source_digest','sha256:'||encode(t.envelope_digest,'hex'),'digest','sha256:'||encode(d.envelope_digest,'hex'),'sequence',d.sequence),'effect_key',zasp_temporal68.effect_identity(o,w,e,r,s,1),'generation',1)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup readback incomplete';END IF;
  IF live_value THEN
   composition_value:=zasp_temporal68.cleanup_composition(o,w,e,t.device_id,r,s);
   IF d.composition IS DISTINCT FROM composition_value OR NOT zasp_sa_multistep_prior.cleanup_delivery_fresh(o,w,e,t.device_id)
    OR NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id,desired_generation,applied_generation,applied_envelope_digest)=(o,w,e,t.device_id,d.desired_generation,d.desired_generation,b.envelope_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup composition changed';END IF;
  END IF;
  v:=v||jsonb_build_array(jsonb_build_object('device_id',t.device_id,'credential_id',t.credential_id,'source_digest','sha256:'||encode(t.envelope_digest,'hex'),'desired_generation',d.desired_generation,'sequence',b.sequence,'digest','sha256:'||encode(b.envelope_digest,'hex'),'composition_digest','sha256:'||encode(digest(convert_to(d.composition::text,'UTF8'),'sha256'),'hex')));
 END LOOP;
 IF jsonb_array_length(v) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup acknowledgement bound';END IF;
 RETURN v;
END $acks$;

CREATE FUNCTION zasp_temporal68.cleanup(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cleanup$
DECLARE o text;w text;e text;r text;s text;op text;intent jsonb;snapshot_value jsonb;env jsonb;acks jsonb;generation_value bigint;audit_value text;marker jsonb;renewal_body jsonb;targets_value jsonb;revision_value bigint;original_digest text;
 c zasp_temporal68.cleanups%ROWTYPE;t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 IF NOT(zasp_temporal68.principal_ready('zasp_temporal_compensation') OR zasp_temporal68.principal_ready('zasp_temporal_executor')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor compensation principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>32768 OR NOT COALESCE(q->>'operation' IN('prepare','read','source','renew','unknown','complete'),false) OR jsonb_typeof(q->'payload') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor compensation request rejected';END IF;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';op:=q->>'operation';env:=q->'payload';
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO c FROM zasp_temporal68.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR UPDATE;
 IF NOT FOUND THEN
  IF op<>'prepare' OR NOT (rr.state IN('cancelled','needs_human','failed','inconclusive','contained') OR zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor compensation not required';END IF;
  snapshot_value:=zasp_temporal68.cleanup_snapshot(o,w,e,r,s);
  IF snapshot_value->>'kind'='applied' THEN PERFORM zasp_ordered_public62.retained_application(o,w,e,r);END IF;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot_value->'targets') x WHERE x->>'state' IN('stored','verified')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor compensation has no source';END IF;
  INSERT INTO zasp_temporal68.cleanups(organization_id,workspace_id,environment_id,run_id,step_id,generation,snapshot,snapshot_digest,state,reason) VALUES(o,w,e,r,s,1,snapshot_value,digest(convert_to(snapshot_value::text,'UTF8'),'sha256'),'pending','execution_stopped') RETURNING * INTO c;
  UPDATE public.zasp_security_agent_runs SET state=CASE WHEN state='cancelled' THEN state ELSE 'needs_human' END,version=version+1,completed_at=COALESCE(completed_at,clock_timestamp()),updated_at=clock_timestamp(),last_error_code='cleanup_required' WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  UPDATE public.zasp_security_agent_steps SET state='cancelled',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state NOT IN('succeeded','inconclusive','cancelled');
  FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') AND state IN('stored','verified') ORDER BY device_id LOOP
   INSERT INTO public.zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version) VALUES(o,w,e,r,s,'cleanup',t.device_id,t.credential_id,1,1);
  END LOOP;
  audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_cleanup',intent->>'effect_key');
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,audit_value,r,s,session_user,'temporal_cleanup_required',c.snapshot_digest,c.snapshot);
 END IF;
 PERFORM zasp_temporal68.cleanup_current(o,w,e,r,s);
 IF op IN('source','renew') THEN
  IF op='renew' THEN
   IF NOT zasp_sa_multistep_prior.closed(env,ARRAY['source_digest','envelope']) OR NOT COALESCE(env->>'source_digest'~'^sha256:[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor cleanup renewal request rejected';END IF;
   original_digest:=env->>'source_digest';env:=env->'envelope';
  END IF;
  IF c.state='cleaned' OR NOT zasp_sa_multistep_prior.closed(env,ARRAY['device_id','credential_id','sequence','policy_version','key_id','issued_at','expires_at','failure_mode','payload_digest','policies','signature','envelope_digest']) OR env->'policies' IS DISTINCT FROM '[]'::jsonb OR env->>'failure_mode' IS DISTINCT FROM 'closed'
   OR NOT COALESCE(env->>'payload_digest'~'^sha256:[a-f0-9]{64}$' AND env->>'envelope_digest'~'^sha256:[a-f0-9]{64}$' AND env->>'key_id'~'^[a-z][a-z0-9_-]{7,63}$',false) OR octet_length(decode(env->>'signature','base64')) IS DISTINCT FROM 64
   OR (env->>'expires_at')::timestamptz IS DISTINCT FROM (env->>'issued_at')::timestamptz+interval '5 minutes' OR (env->>'expires_at')::timestamptz<=clock_timestamp() OR (env->>'issued_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor signed cleanup source rejected';END IF;
  SELECT * INTO t FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version)=(o,w,e,r,s,'cleanup',env->>'device_id',env->>'credential_id',(env->>'sequence')::bigint,(env->>'policy_version')::bigint) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup source identity changed';END IF;
  IF op='renew' THEN
   marker:=zasp_temporal68.cleanup_marker(t);
   IF t.state<>'stored' OR original_digest IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup renewal source changed';END IF;
   IF marker IS DISTINCT FROM env THEN
    IF (marker->>'expires_at')::timestamptz>clock_timestamp() OR (env->>'issued_at')::timestamptz<(marker->>'expires_at')::timestamptz THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup renewal window conflict';END IF;
    SELECT COALESCE(max(revision),0)+1 INTO revision_value FROM zasp_temporal68.cleanup_renewals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,device_id)=(o,w,e,r,s,t.device_id);
    renewal_body:=jsonb_build_object('effect_key',intent->>'effect_key','source',to_jsonb(t)-ARRAY['state','verified_at'],'envelope',env);
    INSERT INTO zasp_temporal68.cleanup_renewals VALUES(o,w,e,r,s,t.device_id,revision_value,renewal_body,digest(convert_to(renewal_body::text,'UTF8'),'sha256'));
    audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_cleanup_renewal',intent->>'effect_key'||chr(31)||t.device_id||chr(31)||revision_value::text);
    INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,audit_value,r,s,session_user,'temporal_cleanup_renewed',digest(convert_to(renewal_body::text,'UTF8'),'sha256'),renewal_body);
   END IF;
  ELSIF t.state='planned' THEN
   UPDATE public.zasp_security_agent_temporary_policy_targets SET state='stored',key_id=env->>'key_id',issued_at=(env->>'issued_at')::timestamptz,expires_at=(env->>'expires_at')::timestamptz,failure_mode='closed',payload_digest=decode(substr(env->>'payload_digest',8),'hex'),policies='[]',signature=decode(env->>'signature','base64'),envelope_digest=decode(substr(env->>'envelope_digest',8),'hex'),stored_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'cleanup',t.device_id);
   generation_value:=public.zasp_policy_deployment_enqueue_device(o,w,e,t.device_id);
   UPDATE public.zasp_security_agent_temporary_policy_targets SET desired_generation=generation_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'cleanup',t.device_id);
  ELSIF (t.key_id,t.issued_at,t.expires_at,t.payload_digest,t.signature,t.envelope_digest) IS DISTINCT FROM(env->>'key_id',(env->>'issued_at')::timestamptz,(env->>'expires_at')::timestamptz,decode(substr(env->>'payload_digest',8),'hex'),decode(env->>'signature','base64'),decode(substr(env->>'envelope_digest',8),'hex')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup source replay conflict';END IF;
 ELSIF env<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor cleanup unexpected payload';
 ELSIF op='unknown' AND c.state<>'cleaned' THEN
  UPDATE zasp_temporal68.cleanups SET state='unknown',version=version+1 WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO c;
 ELSIF op='complete' AND c.state<>'cleaned' THEN
  acks:=zasp_temporal68.cleanup_acks(o,w,e,r,s,true);
  UPDATE public.zasp_security_agent_temporary_policy_targets SET state='verified',verified_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup');
  UPDATE public.zasp_security_agent_controls SET state='disabled',version=version+1 WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'active');
  UPDATE public.zasp_security_agent_effects SET state='cleaned',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  UPDATE zasp_temporal68.effects SET state='cleaned' WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
  UPDATE zasp_temporal68.cleanups SET state='cleaned',version=version+1,completed_at=clock_timestamp(),receipt=jsonb_build_object('effect_key',intent->>'effect_key','snapshot_digest','sha256:'||encode(c.snapshot_digest,'hex'),'targets',acks,'outcome','cleaned') WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO c;
  UPDATE zasp_temporal68.cleanups SET receipt_digest=digest(convert_to(c.receipt::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO c;
  IF c.snapshot->'test'->>'kind'='settled' AND c.snapshot->'test'->'response'->>'outcome'='not_reproduced' THEN
   UPDATE public.zasp_security_agent_runs SET state='remediated',version=version+1,updated_at=clock_timestamp(),last_error_code=NULL WHERE (organization_id,workspace_id,environment_id,run_id,state)=(o,w,e,r,'needs_human');
  END IF;
 END IF;
 PERFORM zasp_temporal68.cleanup_current(o,w,e,r,s);
 IF c.state='cleaned' AND (c.receipt->'targets' IS DISTINCT FROM zasp_temporal68.cleanup_acks(o,w,e,r,s,false) OR c.receipt_digest IS DISTINCT FROM digest(convert_to(c.receipt::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleaned receipt changed';END IF;
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor compensation catalog changed';END IF;
 IF op IN('read','source','renew') THEN
  targets_value:=zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,s);
  IF op='renew' THEN SELECT jsonb_agg(CASE WHEN x->>'device_id'=env->>'device_id' THEN x||jsonb_build_object('envelope_digest',env->>'envelope_digest') ELSE x END ORDER BY x->>'device_id') INTO targets_value FROM jsonb_array_elements(targets_value)x;END IF;
  RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'generation',1,'effect_key',intent->>'effect_key','ttl_seconds',300,'targets',targets_value);
 END IF;
 RETURN to_jsonb(c)||jsonb_build_object('effect_key',intent->>'effect_key');
END $cleanup$;

-- Public reads validate immutable saved proof, not today's delivery composition.
CREATE FUNCTION zasp_temporal68.cleanup_projection(o text,w text,e text,r text,s text) RETURNS zasp_temporal68.cleanups LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $projection$
DECLARE c zasp_temporal68.cleanups%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 SELECT * INTO c FROM zasp_temporal68.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RETURN c;END IF;
 IF c.snapshot IS DISTINCT FROM zasp_temporal68.cleanup_snapshot(o,w,e,r,s) OR c.snapshot_digest IS DISTINCT FROM digest(convert_to(c.snapshot::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public executor cleanup snapshot unavailable';END IF;
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'temporal_cleanup_required');
 IF a.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_cleanup',c.snapshot->>'effect_key') OR a.correlation_id IS DISTINCT FROM a.audit_id OR a.body IS DISTINCT FROM c.snapshot OR a.event_digest IS DISTINCT FROM c.snapshot_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public executor cleanup terminal proof unavailable';END IF;
 IF c.state='cleaned' THEN
  IF c.completed_at IS NULL OR c.receipt_digest IS DISTINCT FROM digest(convert_to(c.receipt::text,'UTF8'),'sha256') OR c.receipt IS DISTINCT FROM jsonb_build_object('effect_key',c.snapshot->>'effect_key','snapshot_digest','sha256:'||encode(c.snapshot_digest,'hex'),'targets',zasp_temporal68.cleanup_acks(o,w,e,r,s,false),'outcome','cleaned')
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'cleaned') AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
   OR c.snapshot->>'kind'='applied' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,control_id,version)=(o,w,e,r,s,'disabled',c.snapshot->'application'->'body'->>'control_id',(c.snapshot->'application'->'body'->>'control_version')::bigint+1))
   OR c.snapshot->>'kind'='partial' AND EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public executor cleanup completion unavailable';END IF;
 ELSIF c.completed_at IS NOT NULL OR c.receipt IS NOT NULL OR c.receipt_digest IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='public executor premature cleanup receipt';END IF;
 RETURN c;
END $projection$;
