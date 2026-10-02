-- Sources keep their established sequence, TTL, current credential and exact
-- compiled containment checks. The enclosing intent replaces lease ownership.
CREATE FUNCTION zasp_temporal68.application(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $application$
DECLARE o text;w text;e text;r text;s text;op text;env jsonb;intent jsonb;ttl integer;generation_value bigint;result_hash bytea;deployment_hash bytea;expires timestamptz;applied timestamptz;control_value text;outcome_value text;deployment_value text;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;receipt public.zasp_sa_multistep_receipts%ROWTYPE;
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor application principal rejected';END IF;
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload']) OR octet_length(q::text)>32768
  OR q->>'operation' NOT IN('read','source','complete') OR jsonb_typeof(q->'payload') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor application request rejected';END IF;
 op:=q->>'operation';env:=q->'payload';o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';
 intent:=zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb));
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 IF intent->>'action_key'<>'create_temporary_policy' OR op='source' AND intent->>'state' NOT IN('started','unknown') OR op='complete' AND intent->>'state' NOT IN('started','unknown','cleanup_pending') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor source intent unavailable';END IF;
 SELECT (plan->'steps'->0->>'ttl_seconds')::integer INTO STRICT ttl FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF op='source' THEN
  IF NOT zasp_sa_multistep_prior.closed(env,ARRAY['device_id','credential_id','sequence','policy_version','key_id','issued_at','expires_at','failure_mode','payload_digest','policies','signature','envelope_digest'])
   OR env->'policies' IS DISTINCT FROM zasp_sa_multistep_prior.application_policies() OR env->>'failure_mode' IS DISTINCT FROM 'closed'
   OR NOT COALESCE(env->>'payload_digest'~'^sha256:[a-f0-9]{64}$' AND env->>'envelope_digest'~'^sha256:[a-f0-9]{64}$' AND env->>'key_id'~'^[a-z][a-z0-9_-]{7,63}$',false)
   OR octet_length(decode(env->>'signature','base64')) IS DISTINCT FROM 64 OR (env->>'issued_at')::timestamptz>clock_timestamp()+interval '5 seconds'
   OR (env->>'expires_at')::timestamptz<=clock_timestamp() OR (env->>'expires_at')::timestamptz IS DISTINCT FROM (env->>'issued_at')::timestamptz+make_interval(secs=>ttl)
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(intent->'snapshot'->'targets') x WHERE (x->>'device_id',x->>'credential_id',x->'sequence',x->'policy_version')=(env->>'device_id',env->>'credential_id',env->'sequence',env->'policy_version')) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor signed source rejected';END IF;
  SELECT * INTO t FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version)=(o,w,e,r,s,'apply',env->>'device_id',env->>'credential_id',(env->>'sequence')::bigint,(env->>'policy_version')::bigint) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor source identity changed';END IF;
  IF t.state='planned' THEN
   UPDATE public.zasp_security_agent_temporary_policy_targets SET state='stored',key_id=env->>'key_id',issued_at=(env->>'issued_at')::timestamptz,expires_at=(env->>'expires_at')::timestamptz,failure_mode='closed',payload_digest=decode(substr(env->>'payload_digest',8),'hex'),policies=env->'policies',signature=decode(env->>'signature','base64'),envelope_digest=decode(substr(env->>'envelope_digest',8),'hex'),stored_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'apply',t.device_id);
   generation_value:=public.zasp_policy_deployment_enqueue_device(o,w,e,t.device_id);
   UPDATE public.zasp_security_agent_temporary_policy_targets SET desired_generation=generation_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'apply',t.device_id);
  ELSIF (t.key_id,t.issued_at,t.expires_at,t.failure_mode,t.payload_digest,t.policies,t.signature,t.envelope_digest) IS DISTINCT FROM (env->>'key_id',(env->>'issued_at')::timestamptz,(env->>'expires_at')::timestamptz,'closed',decode(substr(env->>'payload_digest',8),'hex'),env->'policies',decode(env->>'signature','base64'),decode(substr(env->>'envelope_digest',8),'hex')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor source replay conflict';END IF;
 ELSIF env<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='executor application unexpected payload';
 ELSIF op='complete' THEN
  PERFORM zasp_sa_multistep_prior.deployment_verified(o,w,e,r,s);
  SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  IF NOT FOUND THEN
   IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply'))
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.phase)=(o,w,e,r,s,'apply') AND NOT EXISTS(SELECT 1 FROM zasp_temporal68.deliveries d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id,d.generation,d.phase,d.device_id,d.state,d.source_digest,d.desired_generation)=(o,w,e,r,s,1,'apply',x.device_id,'acknowledged',x.envelope_digest,x.desired_generation) AND d.read_at IS NOT NULL)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor application delivery receipt absent';END IF;
   SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
   UPDATE public.zasp_security_agent_temporary_policy_targets SET state='verified',verified_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') AND state='stored';
   SELECT digest(st.input_digest||decode(string_agg(encode(envelope_digest,'hex'),'' ORDER BY device_id),'hex'),'sha256'),digest(convert_to(jsonb_agg(jsonb_build_array(device_id,credential_id,sequence,policy_version,desired_generation,encode(envelope_digest,'hex')) ORDER BY device_id)::text,'UTF8'),'sha256'),min(expires_at),max(verified_at) INTO result_hash,deployment_hash,expires,applied FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
   control_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_control',r||chr(31)||s);
   outcome_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_effect',r||chr(31)||s||chr(31)||'apply');
   deployment_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_deployment',r||chr(31)||s||chr(31)||encode(deployment_hash,'hex'));
   INSERT INTO public.zasp_security_agent_controls(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at) VALUES(o,w,e,control_value,r,s,'create_temporary_policy',e,'active',expires);
   UPDATE public.zasp_security_agent_effects SET state='cleanup_pending',outcome_id=outcome_value,result_digest=result_hash,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
   UPDATE public.zasp_security_agent_steps SET state='succeeded',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
   UPDATE public.zasp_security_agent_runs SET version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
   UPDATE zasp_temporal68.effects SET state='cleanup_pending',completed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,generation)=(o,w,e,r,s,1);
   INSERT INTO public.zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body)
    VALUES(o,w,e,r,decode(intent->'snapshot'->>'plan_hash','hex'),s,'create_temporary_policy',st.input_digest,result_hash,'temporary_policy_applied.v1',1,jsonb_build_object('deployment_id',deployment_value,'control_id',control_value,'control_version',1,'outcome_id',outcome_value,'applied_at',to_char(applied AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))) RETURNING * INTO receipt;
  END IF;
  IF NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor application evidence changed';END IF;
 END IF;
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 IF NOT zasp_temporal68.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='executor application catalog changed';END IF;
 IF op='complete' THEN RETURN jsonb_build_object('effect_key',intent->>'effect_key','receipt_kind',receipt.receipt_kind,'receipt',receipt.body,'result_digest','sha256:'||encode(receipt.result_digest,'hex'));END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'generation',1,'effect_key',intent->>'effect_key','ttl_seconds',ttl,'targets',zasp_sa_multistep_prior.application_targets(o,w,e,r,s));
END $application$;
