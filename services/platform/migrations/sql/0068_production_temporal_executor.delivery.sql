CREATE TABLE zasp_temporal68.deliveries(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,generation bigint NOT NULL,
 phase text NOT NULL CHECK(phase IN('apply','cleanup')),device_id text NOT NULL,credential_id text NOT NULL,
 source_sequence bigint NOT NULL,source_digest bytea NOT NULL,desired_generation bigint NOT NULL,sequence bigint NOT NULL,
 composition jsonb NOT NULL CHECK(octet_length(composition::text)<=7340032),
 state text NOT NULL CHECK(state IN('prepared','stored','read','acknowledged')),envelope jsonb,envelope_digest bytea,read_at timestamptz,acknowledged_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id,generation) REFERENCES zasp_temporal68.effects(organization_id,workspace_id,environment_id,run_id,step_id,generation),
 UNIQUE(organization_id,workspace_id,environment_id,device_id,sequence));
ALTER TABLE zasp_temporal68.deliveries OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.deliveries USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

CREATE TABLE zasp_temporal68.delivery_revisions(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,device_id text NOT NULL,sequence bigint NOT NULL,
 body jsonb NOT NULL CHECK(octet_length(body::text)<=8388608),body_digest bytea NOT NULL CHECK(octet_length(body_digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id,device_id,sequence),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id));
ALTER TABLE zasp_temporal68.delivery_revisions OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal68.delivery_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal68.delivery_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal68.delivery_revisions USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal68.delivery_revisions FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();

CREATE FUNCTION zasp_temporal68.delivery_history(t public.zasp_security_agent_temporary_policy_targets) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $history$
DECLARE x zasp_temporal68.delivery_revisions%ROWTYPE;b public.zasp_runtime_gateway_policy_bundles%ROWTYPE;body_value jsonb;readback jsonb;
BEGIN
 FOR x IN SELECT * FROM zasp_temporal68.delivery_revisions WHERE (organization_id,workspace_id,environment_id,run_id,step_id,device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.device_id) ORDER BY sequence LOOP
  body_value:=x.body;
  IF x.body_digest IS DISTINCT FROM digest(convert_to(body_value::text,'UTF8'),'sha256') OR body_value->'sequence' IS DISTINCT FROM to_jsonb(x.sequence)
   OR (body_value->>'organization_id',body_value->>'workspace_id',body_value->>'environment_id',body_value->>'run_id',body_value->>'step_id',body_value->>'device_id',body_value->>'credential_id',body_value->>'phase') IS DISTINCT FROM(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.device_id,t.credential_id,'cleanup')
   OR body_value->'generation' IS DISTINCT FROM '1'::jsonb OR body_value->'source_digest' IS DISTINCT FROM to_jsonb(t.envelope_digest) OR body_value->'source_sequence' IS DISTINCT FROM to_jsonb(t.sequence)
   OR NOT EXISTS(SELECT 1 FROM zasp_temporal68.deliveries d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id,d.device_id,d.phase)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.device_id,'cleanup') AND d.sequence>x.sequence) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery history changed';END IF;
  IF body_value->>'state'<>'prepared' THEN
   SELECT * INTO b FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(t.organization_id,t.workspace_id,t.environment_id,t.device_id,x.sequence);
   readback:=zasp_sa_multistep_prior.cleanup_bundle_snapshot(b);
   IF to_jsonb(b.envelope_digest) IS DISTINCT FROM body_value->'envelope_digest' OR b.credential_id IS DISTINCT FROM t.credential_id
    OR (readback-ARRAY['issued_at','expires_at']) IS DISTINCT FROM((body_value->'envelope')-ARRAY['issued_at','expires_at']) OR (b.issued_at,b.expires_at) IS DISTINCT FROM((body_value->'envelope'->>'issued_at')::timestamptz,(body_value->'envelope'->>'expires_at')::timestamptz) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor historical signed delivery changed';END IF;
  END IF;
  IF body_value->>'state'='acknowledged' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,'temporal_cleanup_delivery_finish') AND a.event_digest=x.body_digest AND a.correlation_id=a.audit_id
   AND a.body=jsonb_build_object('composition',body_value->'composition','request',jsonb_build_object('device_id',t.device_id,'source_digest','sha256:'||encode(t.envelope_digest,'hex'),'digest','sha256:'||encode(b.envelope_digest,'hex'),'sequence',x.sequence),'effect_key',zasp_temporal68.effect_identity(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,1),'generation',1)
   AND a.audit_id=public.zasp_discovery_canonical_id(t.organization_id,t.workspace_id,t.environment_id,'security_agent_temporal_delivery',zasp_temporal68.effect_identity(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,1)||chr(31)||'cleanup'||chr(31)||t.device_id||chr(31)||x.sequence::text)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor historical acknowledgement changed';END IF;
 END LOOP;
END $history$;

CREATE FUNCTION zasp_temporal68.delivery(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $delivery$
DECLARE o text;w text;e text;r text;s text;d text;op text;phase_value text;p jsonb;env jsonb;intent jsonb;composition_value jsonb;sequence_value bigint;audit_value text;response_value jsonb;readback jsonb;refresh_value boolean:=false;generation_value bigint;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;work public.zasp_policy_deployment_work%ROWTYPE;b public.zasp_runtime_gateway_policy_bundles%ROWTYPE;v zasp_temporal68.deliveries%ROWTYPE;
BEGIN
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR NOT zasp_sa_multistep_prior.deployment_wire(q,true)
  OR NOT COALESCE(q->>'operation' IN('prepare','store','read','ack'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor delivery request rejected';END IF;
 op:=q->>'operation';p:=q->'payload';o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';d:=p->>'device_id';env:=p->'envelope';
 phase_value:=p->>'phase';
 IF NOT COALESCE(public.zasp_valid_product_id(d),false) OR NOT COALESCE(phase_value IN('apply','cleanup'),false)
  OR NOT zasp_sa_multistep_prior.closed(p,CASE op WHEN 'prepare' THEN ARRAY['device_id','phase'] WHEN 'store' THEN ARRAY['device_id','phase','envelope','digest'] ELSE ARRAY['device_id','phase','digest'] END)
  OR op<>'prepare' AND NOT COALESCE(p->>'digest'~'^sha256:[a-f0-9]{64}$',false)
  OR NOT(zasp_temporal68.principal_ready('zasp_temporal_executor') OR (phase_value='cleanup' OR op IN('read','ack')) AND zasp_temporal68.principal_ready('zasp_temporal_compensation')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor delivery authority rejected';END IF;
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 IF intent->>'action_key'<>'create_temporary_policy' OR intent->>'state' NOT IN('started','unknown','cleanup_pending','cleaned') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery intent unavailable';END IF;
 IF phase_value='cleanup' THEN PERFORM zasp_temporal68.cleanup_current(o,w,e,r,s);
 ELSIF op IN('prepare','store') THEN PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);END IF;
 SELECT * INTO t FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,phase_value,d);
 SELECT * INTO work FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);
 IF t.state NOT IN('stored','verified') OR t.envelope_digest IS NULL OR t.desired_generation IS NULL OR work.device_id IS NULL OR work.state='leased' OR work.lease_token IS NOT NULL OR work.lease_owner IS NOT NULL OR work.lease_expires_at IS NOT NULL
  OR (CASE WHEN phase_value='cleanup' THEN work.desired_generation<t.desired_generation ELSE work.desired_generation IS DISTINCT FROM t.desired_generation END) OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(intent->'snapshot'->'targets') x WHERE x->>'device_id'=d AND x->>'credential_id'=t.credential_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery source or owner changed';END IF;
 generation_value:=work.desired_generation;
 composition_value:=CASE WHEN phase_value='cleanup' THEN zasp_temporal68.cleanup_composition(o,w,e,d,r,s) ELSE zasp_sa_multistep_prior.deployment_composition(o,w,e,d) END;
 SELECT * INTO v FROM zasp_temporal68.deliveries WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,phase_value,d) FOR UPDATE;
 IF phase_value='cleanup' AND (zasp_temporal68.cleanup_marker(t)->>'expires_at')::timestamptz<=clock_timestamp() AND v.state IS DISTINCT FROM 'acknowledged' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup signing marker expired';END IF;
 IF phase_value='cleanup' THEN
  PERFORM zasp_temporal68.delivery_history(t);
  refresh_value:=v.run_id IS NOT NULL AND (v.composition IS DISTINCT FROM composition_value OR v.desired_generation<>generation_value OR v.envelope IS NOT NULL AND (v.envelope->>'expires_at')::timestamptz<=clock_timestamp()+interval '1 minute');
  IF refresh_value THEN
   IF op<>'prepare' OR (zasp_temporal68.cleanup_marker(t)->>'expires_at')::timestamptz<=clock_timestamp() OR NOT EXISTS(SELECT 1 FROM zasp_temporal68.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) AND state IN('pending','unknown')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup recomposition requires fresh authority';END IF;
   INSERT INTO zasp_temporal68.delivery_revisions VALUES(o,w,e,r,s,d,v.sequence,to_jsonb(v),digest(convert_to(to_jsonb(v)::text,'UTF8'),'sha256'));
  END IF;
 END IF;
 IF v.run_id IS NULL OR refresh_value THEN
  IF op<>'prepare' OR NOT refresh_value AND work.applied_generation>=work.desired_generation THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery not prepared';END IF;
  SELECT COALESCE(max(x.sequence)+1,1) INTO sequence_value FROM (SELECT sequence FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d) UNION ALL SELECT sequence FROM zasp_temporal68.deliveries WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d) UNION ALL SELECT sequence FROM zasp_temporal68.delivery_revisions WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d))x;
  IF sequence_value NOT BETWEEN 1 AND 999999999 OR NOT zasp_sa_multistep_prior.deployment_signable(o,w,e,d,sequence_value,composition_value->'policies') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery signing bound rejected';END IF;
  INSERT INTO zasp_temporal68.deliveries VALUES(o,w,e,r,s,1,phase_value,d,t.credential_id,t.sequence,t.envelope_digest,generation_value,sequence_value,composition_value,'prepared',NULL,NULL,NULL,NULL)
   ON CONFLICT(organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id) DO UPDATE SET desired_generation=EXCLUDED.desired_generation,sequence=EXCLUDED.sequence,composition=EXCLUDED.composition,state='prepared',envelope=NULL,envelope_digest=NULL,read_at=NULL,acknowledged_at=NULL WHERE refresh_value AND zasp_temporal68.deliveries.phase='cleanup' RETURNING * INTO v;
 END IF;
 IF (v.source_sequence,v.source_digest,v.credential_id,v.desired_generation,v.composition) IS DISTINCT FROM(t.sequence,t.envelope_digest,t.credential_id,generation_value,composition_value)
  OR (composition_value->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery snapshot changed';END IF;
 IF op='store' THEN
  IF NOT zasp_sa_multistep_prior.closed(env,ARRAY['contract_version','key_id','algorithm','audience','organization_id','workspace_id','environment_id','device_id','sequence','policy_version','issued_at','expires_at','failure_mode','payload_digest','policies','signature'])
   OR env->'contract_version' IS DISTINCT FROM '1'::jsonb OR env->>'algorithm' IS DISTINCT FROM 'Ed25519' OR env->>'audience' IS DISTINCT FROM 'runtime-gateway-policy'
   OR (env->>'organization_id',env->>'workspace_id',env->>'environment_id',env->>'device_id') IS DISTINCT FROM(o,w,e,d)
   OR env->'sequence' IS DISTINCT FROM to_jsonb(v.sequence) OR env->'policy_version' IS DISTINCT FROM to_jsonb(v.sequence) OR env->'policies' IS DISTINCT FROM v.composition->'policies'
   OR env->>'failure_mode' IS DISTINCT FROM 'closed' OR (env->>'expires_at')::timestamptz>(v.composition->>'expires_at')::timestamptz OR (env->>'expires_at')::timestamptz<t.expires_at OR (env->>'expires_at')::timestamptz<=clock_timestamp()
   OR (env->>'issued_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR octet_length(zasp_sa_multistep_prior.deployment_json(env))>1048576 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor delivery envelope rejected';END IF;
  IF v.state='prepared' THEN
   INSERT INTO public.zasp_runtime_gateway_policy_bundles(organization_id,workspace_id,environment_id,device_id,credential_id,sequence,policy_version,key_id,algorithm,audience,issued_at,expires_at,failure_mode,payload_digest,policies,signature,envelope_digest)
    VALUES(o,w,e,d,v.credential_id,v.sequence,v.sequence,env->>'key_id','Ed25519','runtime-gateway-policy',(env->>'issued_at')::timestamptz,(env->>'expires_at')::timestamptz,'closed',decode(env->>'payload_digest','hex'),env->'policies',decode(translate(env->>'signature','-_','+/')||repeat('=',(4-length(env->>'signature')%4)%4),'base64'),decode(substr(p->>'digest',8),'hex'));
   UPDATE zasp_temporal68.deliveries SET state='stored',envelope=env,envelope_digest=decode(substr(p->>'digest',8),'hex') WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,phase_value,d) RETURNING * INTO v;
  ELSIF v.envelope IS DISTINCT FROM env OR v.envelope_digest IS DISTINCT FROM decode(substr(p->>'digest',8),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery replay conflict';END IF;
 ELSIF op IN('read','ack') THEN
  SELECT * INTO b FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(o,w,e,d,v.sequence);
  readback:=zasp_sa_multistep_prior.cleanup_bundle_snapshot(b);
  IF v.state='prepared' OR b.envelope_digest IS DISTINCT FROM v.envelope_digest OR v.envelope_digest IS DISTINCT FROM decode(substr(p->>'digest',8),'hex') OR b.credential_id IS DISTINCT FROM v.credential_id
   OR (readback-ARRAY['issued_at','expires_at']) IS DISTINCT FROM(v.envelope-ARRAY['issued_at','expires_at']) OR (b.issued_at,b.expires_at) IS DISTINCT FROM((v.envelope->>'issued_at')::timestamptz,(v.envelope->>'expires_at')::timestamptz) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery readback changed';END IF;
  IF op='read' AND v.read_at IS NULL THEN
   UPDATE zasp_temporal68.deliveries SET state='read',read_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,phase_value,d) RETURNING * INTO v;
  ELSIF op='ack' AND v.state<>'acknowledged' THEN
   IF v.read_at IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery readback absent';END IF;
   UPDATE public.zasp_policy_deployment_work SET applied_generation=v.desired_generation,applied_envelope_digest=v.envelope_digest,state='scheduled',attempt=0,available_at=LEAST(clock_timestamp()+interval '12 hours',b.expires_at-interval '1 minute'),updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);
   UPDATE zasp_temporal68.deliveries SET state='acknowledged',acknowledged_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(o,w,e,r,s,1,phase_value,d) RETURNING * INTO v;
   audit_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_temporal_delivery',intent->>'effect_key'||chr(31)||phase_value||chr(31)||d||CASE WHEN phase_value='cleanup' THEN chr(31)||v.sequence::text ELSE '' END);
   INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
    VALUES(o,w,e,audit_value,audit_value,r,s,session_user,CASE WHEN phase_value='cleanup' THEN 'temporal_cleanup_delivery_finish' ELSE 'ordered_delivery_finish' END,digest(convert_to(to_jsonb(v)::text,'UTF8'),'sha256'),jsonb_build_object('composition',v.composition,'request',jsonb_build_object('device_id',d,'source_digest','sha256:'||encode(t.envelope_digest,'hex'),'digest','sha256:'||encode(v.envelope_digest,'hex'),'sequence',v.sequence),'effect_key',intent->>'effect_key','generation',1));
  END IF;
 END IF;
 IF phase_value='cleanup' THEN PERFORM zasp_temporal68.cleanup_current(o,w,e,r,s);
 ELSIF op IN('prepare','store') THEN PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);END IF;
 IF v.composition IS DISTINCT FROM (CASE WHEN phase_value='cleanup' THEN zasp_temporal68.cleanup_composition(o,w,e,d,r,s) ELSE zasp_sa_multistep_prior.deployment_composition(o,w,e,d) END) OR (v.composition->>'expires_at')::timestamptz<=clock_timestamp()+interval '1 minute' OR NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor delivery authority changed after wait';END IF;
 IF phase_value='cleanup' THEN PERFORM zasp_temporal68.delivery_history(t);END IF;
 IF phase_value='cleanup' AND v.state<>'acknowledged' AND (zasp_temporal68.cleanup_marker(t)->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor cleanup marker expired after wait';END IF;
 response_value:=to_jsonb(v)||jsonb_build_object('effect_key',intent->>'effect_key');
 IF NOT zasp_sa_multistep_prior.deployment_wire(response_value,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor delivery response bound rejected';END IF;
 RETURN response_value;
END $delivery$;
