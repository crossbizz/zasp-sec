-- Private release61-only application producer. It does not dispatch the test,
-- claim cleanup, or install a generic worker route. Legacy lanes stay fenced.
CREATE FUNCTION zasp_sa_multistep_prior.application_lock(o text,w text,e text,r text,d text DEFAULT NULL) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $lock$
DECLARE device record;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered organization absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered budget absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered run absent';END IF;
 PERFORM 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 PERFORM 1 FROM public.zasp_sa_multistep_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index FOR UPDATE;
 PERFORM 1 FROM public.zasp_sa_multistep_dependencies WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_index FOR SHARE;
 PERFORM 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id,action_key FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY control_id FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id,phase,device_id FOR UPDATE;
 -- Deployment and safety writers have independent source/work ordering.
 -- Never wait on that shared domain while owning ordered authority.
 PERFORM 1 FROM public.zasp_policy_deployment_fairness WHERE organization_id=o FOR UPDATE NOWAIT;
 PERFORM 1 FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (d IS NULL OR device_id=d) ORDER BY device_id FOR UPDATE NOWAIT;
 PERFORM 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND run_id<>r AND (d IS NULL OR device_id=d) ORDER BY run_id,step_id,phase,device_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (d IS NULL OR id=d) ORDER BY id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (d IS NULL OR device_id=d) ORDER BY id FOR SHARE NOWAIT;
 FOR device IN SELECT id FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (d IS NULL OR id=d) ORDER BY id LOOP
  IF NOT pg_try_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,device.id,'policy-deployment-source-sequence'),0)) THEN
   RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered source sequence busy';END IF;
 END LOOP;
 PERFORM 1 FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND (d IS NULL OR device_id=d) ORDER BY device_id,sequence FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind)=(o,w,e,'policy') ORDER BY id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_security_agent_provider_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY attempt FOR SHARE;
 PERFORM 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR UPDATE;
 PERFORM 1 FROM zasp_sa_multistep_prior.admissions WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
END $lock$;

CREATE FUNCTION zasp_sa_multistep_prior.application_current(o text,w text,e text,r text,s text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
DECLARE a public.zasp_security_agent_approvals%ROWTYPE;m public.zasp_identity_memberships%ROWTYPE;grant_row public.zasp_authorized_scopes%ROWTYPE;
BEGIN
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,true);
 IF s IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key)=(o,w,e,r,s,0,'create_temporary_policy') AND state IN('authorized','executing','succeeded'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects f WHERE (f.organization_id,f.workspace_id,f.environment_id,f.run_id)=(o,w,e,r) AND (f.step_id<>s OR f.action_key<>'create_temporary_policy'
   OR f.input_digest IS DISTINCT FROM (SELECT input_digest FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.run_id,b.step_id,b.action_key,b.input_digest)=(o,w,e,r,s,f.action_key,f.input_digest)))) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application step unavailable';END IF;
 SELECT * INTO a FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state)=(o,w,e,r,s,'approved');
 IF a.approval_id IS NULL OR a.version<>2 OR a.approver_id IS NULL OR a.approver_id=a.requester_id OR a.fresh_auth_at IS NULL OR a.decided_at IS NULL
  OR a.expires_at<=clock_timestamp() OR a.fresh_auth_at<a.decided_at-interval '5 minutes' OR a.fresh_auth_at>a.decided_at+interval '5 seconds' THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application approval unavailable';END IF;
 SELECT * INTO m FROM public.zasp_identity_memberships WHERE (organization_id,principal_id)=(o,a.approver_id) FOR SHARE;
 grant_row:=zasp_sa_multistep_prior.lock_scope(o,w,e,a.approver_id);
 IF m.active IS DISTINCT FROM true OR NOT COALESCE(public.zasp_effective_scope_permissions(grant_row.permissions,m.role) ?& ARRAY['view','manage_workflows','run_tests'],false) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered application approver unavailable';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id)=(o,w,e,r)
  AND (t.step_id<>s OR t.phase<>'apply' OR t.action_key<>'create_temporary_policy' OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.id,d.state)=(o,w,e,t.device_id,'active'))
   OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials g WHERE (g.organization_id,g.workspace_id,g.environment_id,g.device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1)
   OR t.state<>'planned' AND (t.expires_at<=clock_timestamp() OR t.failure_mode IS DISTINCT FROM 'closed' OR t.policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()
    OR t.expires_at IS DISTINCT FROM t.issued_at+make_interval(secs=>(SELECT (plan->'steps'->0->>'ttl_seconds')::integer FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)))
    OR t.desired_generation IS NULL OR NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.desired_generation)=(o,w,e,t.device_id,t.desired_generation))))) THEN
  RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application target changed';END IF;
END $current$;

-- This dormant adapter supports exactly the two compiled containment policies.
CREATE FUNCTION zasp_sa_multistep_prior.application_policies() RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $policies$
 SELECT jsonb_agg(jsonb_build_object('id',id,'trigger',trigger,'action','block','conditions',jsonb_build_array(jsonb_build_object('field',field,'operator','present','value','')),'rego',rego,'digest',encode(digest(convert_to(rego,'UTF8'),'sha256'),'hex')) ORDER BY id)
 FROM (SELECT id,trigger,field,format(E'package zasp.runtime\n\nimport rego.v1\n\npolicy_id := "%s"\ntrigger := "%s"\n\ndefault decision := {"action": "monitor", "matched": false}\n\ndecision := {"action": "block", "matched": true} if {\n\tinput["%s"] != ""\n}\n',id,trigger,field) AS rego FROM (VALUES('temporary-containment-http-v1','http_request','http.method'),('temporary-containment-mcp-v1','tool_call','tool.name')) v(id,trigger,field)) compiled
$policies$;

CREATE FUNCTION zasp_sa_multistep_prior.application_targets(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $targets$
 SELECT jsonb_agg(jsonb_build_object('device_id',device_id,'credential_id',credential_id,'sequence',sequence,'policy_version',policy_version,'state',state,'desired_generation',COALESCE(desired_generation,0),'envelope_digest',COALESCE('sha256:'||encode(envelope_digest,'hex'),'')) ORDER BY device_id) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply')
$targets$;

-- Reuse the exact release60 source adapter under the stronger outer locks.
-- It is copied privately, never substituted for the fenced public entry.
DO $source$
DECLARE d text;needle text:='CREATE OR REPLACE FUNCTION public.zasp_policy_deployment_store_temporary_source(';
BEGIN
 SELECT definition INTO STRICT d FROM zasp_sa_multistep_prior.functions WHERE signature='public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered source predecessor rejected';END IF;
 EXECUTE replace(d,needle,'CREATE FUNCTION zasp_sa_multistep_prior.application_source(');
END $source$;

CREATE FUNCTION zasp_sa_multistep_prior.application(checksum_value text,fingerprint_value text,request_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $application$
<<action_body>>
DECLARE o text;w text;e text;r text;s text;op text;worker text;token text;key text;envelope jsonb;request_digest bytea;audit_id text;outcome_id text;control_id text;deployment_id text;
 rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 old_audit public.zasp_security_agent_audit%ROWTYPE;target public.zasp_security_agent_temporary_policy_targets%ROWTYPE;device record;
 result_value jsonb;targets jsonb;result_hash bytea;deployment_hash bytea;ttl integer;lease_until timestamptz;expires timestamptz;applied timestamptz;prior_lease timestamptz;replay boolean;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered application requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.closed(request_value,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','worker_id','lease_token','run_version','effect_version','lease_seconds','envelope']) OR octet_length(request_value::text)>32768 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered application input rejected';END IF;
 FOREACH key IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(request_value->>key),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered application identity rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['worker_id','lease_token'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR length(btrim(request_value->>key)) NOT BETWEEN 1 AND 128 OR (request_value->>key)~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered application lease rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['run_version','effect_version','lease_seconds'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'number' OR (request_value->>key)!~'^(0|[1-9][0-9]{0,5})$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered application version rejected';END IF;
 END LOOP;
 o:=request_value->>'organization_id';w:=request_value->>'workspace_id';e:=request_value->>'environment_id';r:=request_value->>'run_id';s:=request_value->>'step_id';op:=request_value->>'operation';worker:=request_value->>'worker_id';token:=request_value->>'lease_token';envelope:=request_value->'envelope';
 IF NOT COALESCE(op IN('claim','heartbeat','store','complete'),false) OR (request_value->>'run_version')::integer<1 OR length(token)<16 OR (request_value->>'lease_seconds')::integer NOT BETWEEN 30 AND 300 OR jsonb_typeof(envelope) IS DISTINCT FROM 'object' OR op<>'store' AND envelope<>'{}'::jsonb THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered application operation rejected';END IF;
 IF NOT COALESCE(public.zasp_security_agent_action_principal_ready(),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered application principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered application release unavailable';END IF;
 PERFORM zasp_sa_multistep_prior.application_lock(o,w,e,r);
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 SELECT (plan->'steps'->0->>'ttl_seconds')::integer INTO ttl FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 request_digest:=digest(convert_to(request_value::text,'UTF8'),'sha256');
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_application',r||chr(31)||s||chr(31)||encode(request_digest,'hex'));
 control_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_control',r||chr(31)||s);
 outcome_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_effect',r||chr(31)||s||chr(31)||'apply');
 SELECT a.* INTO old_audit FROM public.zasp_security_agent_audit a WHERE a.organization_id=o AND a.audit_id=action_body.audit_id FOR SHARE;
 replay:=FOUND;
 IF replay THEN
  result_value:=old_audit.body->'response';
  IF old_audit.event_digest IS DISTINCT FROM request_digest OR old_audit.body->'request' IS DISTINCT FROM request_value-'lease_token'
   OR result_value->'run_version' IS DISTINCT FROM to_jsonb(rr.version) OR result_value->'step_version' IS DISTINCT FROM to_jsonb(st.version)
   OR result_value->'effect_version' IS DISTINCT FROM to_jsonb(fx.version) OR result_value->>'effect_state' IS DISTINCT FROM fx.state
   OR result_value->'targets' IS DISTINCT FROM zasp_sa_multistep_prior.application_targets(o,w,e,r,s)
   OR (old_audit.body->>'lease_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application replay changed';END IF;
  IF op='complete' THEN
   IF NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered receipt missing';END IF;
  ELSIF fx.state<>'leased' OR fx.lease_owner IS DISTINCT FROM worker OR fx.lease_token IS DISTINCT FROM token OR fx.lease_expires_at IS NULL OR fx.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application replay lease lost';END IF;
 ELSE
  IF rr.version<>(request_value->>'run_version')::bigint OR COALESCE(fx.version,0)<>(request_value->>'effect_version')::bigint THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application version changed';END IF;
  IF op='claim' THEN
   IF fx.run_id IS NULL THEN
    IF st.state<>'authorized' OR EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered claim is not ready';END IF;
    SELECT COALESCE(jsonb_agg(jsonb_build_object('id',d.id,'credential_id',g.id) ORDER BY d.id),'[]'::jsonb) INTO targets FROM public.zasp_gateway_devices d JOIN LATERAL(SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d.id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1) g ON true WHERE (d.organization_id,d.workspace_id,d.environment_id,d.state)=(o,w,e,'active');
    IF jsonb_array_length(targets) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered claim target bound rejected';END IF;
    INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,lease_owner,lease_token,lease_expires_at,attempt)
     VALUES(o,w,e,r,s,'create_temporary_policy',st.input_digest,'leased',worker,token,clock_timestamp()+make_interval(secs=>(request_value->>'lease_seconds')::integer),1);
    FOR device IN SELECT * FROM jsonb_to_recordset(targets) AS t(id text,credential_id text) LOOP
     INSERT INTO public.zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version) VALUES(o,w,e,r,s,'apply',device.id,device.credential_id,1,1);
    END LOOP;
    IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered claim has no gateway';END IF;
    INSERT INTO public.zasp_security_agent_step_reservations(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest) VALUES(o,w,e,r,s,'create_temporary_policy',st.input_digest);
    UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
   ELSE
    IF st.state<>'executing' OR fx.state<>'leased' OR fx.lease_expires_at IS NULL OR fx.lease_expires_at>clock_timestamp() OR fx.lease_token=token OR fx.attempt>=100
     OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'create_temporary_policy',st.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered claim lease unavailable';END IF;
    -- Stored sources survive recovery. Neither a receipt nor verification is
    -- inferred from lease expiry or an uncertain external worker outcome.
    UPDATE public.zasp_security_agent_effects SET lease_owner=worker,lease_token=token,lease_expires_at=clock_timestamp()+make_interval(secs=>(request_value->>'lease_seconds')::integer),attempt=attempt+1,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
   END IF;
   UPDATE public.zasp_security_agent_runs SET version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  ELSE
   IF st.state<>'executing' OR fx.state IS DISTINCT FROM 'leased' OR fx.lease_owner IS DISTINCT FROM worker OR fx.lease_token IS DISTINCT FROM token OR fx.lease_expires_at IS NULL OR fx.lease_expires_at<=clock_timestamp()
    OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'create_temporary_policy',st.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application lease lost';END IF;
   prior_lease:=fx.lease_expires_at;
   IF op='heartbeat' THEN
    UPDATE public.zasp_security_agent_effects SET lease_expires_at=GREATEST(lease_expires_at,clock_timestamp()+make_interval(secs=>(request_value->>'lease_seconds')::integer)),version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
   ELSIF op='store' THEN
    IF NOT zasp_sa_multistep_prior.closed(envelope,ARRAY['device_id','credential_id','sequence','policy_version','key_id','issued_at','expires_at','failure_mode','payload_digest','policies','signature','envelope_digest'])
     OR envelope->'policies' IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()
     OR envelope->>'failure_mode' IS DISTINCT FROM 'closed' OR (envelope->>'issued_at')::timestamptz>clock_timestamp()+interval '5 seconds'
     OR (envelope->>'expires_at')::timestamptz<=clock_timestamp() OR (envelope->>'payload_digest')!~'^sha256:[a-f0-9]{64}$' OR (envelope->>'envelope_digest')!~'^sha256:[a-f0-9]{64}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered source envelope rejected';END IF;
    PERFORM zasp_sa_multistep_prior.application_source(o,w,e,r,s,'apply',worker,token,envelope->>'device_id',envelope->>'credential_id',(envelope->>'sequence')::bigint,(envelope->>'policy_version')::bigint,envelope->>'key_id',(envelope->>'issued_at')::timestamptz,(envelope->>'expires_at')::timestamptz,envelope->>'failure_mode',decode(substring(envelope->>'payload_digest' FROM 8),'hex'),envelope->'policies',decode(envelope->>'signature','base64'),decode(substring(envelope->>'envelope_digest' FROM 8),'hex'));
    UPDATE public.zasp_security_agent_effects SET version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
   ELSE
    PERFORM zasp_sa_multistep_prior.deployment_verified(o,w,e,r,s);
    IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply'))
     OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id)=(o,w,e,r,s)
      AND (t.phase<>'apply' OR t.state<>'stored' OR NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d JOIN public.zasp_runtime_gateway_policy_bundles bundle ON (bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.envelope_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.applied_envelope_digest)
       WHERE (d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.desired_generation,d.applied_generation)=(o,w,e,t.device_id,t.desired_generation,t.desired_generation)
        AND bundle.credential_id=t.credential_id AND bundle.expires_at>=t.expires_at AND bundle.expires_at>clock_timestamp() AND bundle.failure_mode='closed' AND bundle.policies @> t.policies))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment is not verified';END IF;
    UPDATE public.zasp_security_agent_temporary_policy_targets SET state='verified',verified_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
    SELECT digest(st.input_digest||decode(string_agg(encode(envelope_digest,'hex'),'' ORDER BY device_id),'hex'),'sha256'),digest(convert_to(jsonb_agg(jsonb_build_array(device_id,credential_id,sequence,policy_version,desired_generation,encode(envelope_digest,'hex')) ORDER BY device_id)::text,'UTF8'),'sha256'),min(expires_at),max(verified_at) INTO result_hash,deployment_hash,expires,applied FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
    deployment_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_deployment',r||chr(31)||s||chr(31)||encode(deployment_hash,'hex'));
    INSERT INTO public.zasp_security_agent_controls(organization_id,workspace_id,environment_id,control_id,run_id,step_id,action_key,target_id,state,expires_at) VALUES(o,w,e,control_id,r,s,'create_temporary_policy',e,'active',expires);
    UPDATE public.zasp_security_agent_effects SET state='cleanup_pending',outcome_id=action_body.outcome_id,result_digest=result_hash,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=expires WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
    UPDATE public.zasp_security_agent_steps SET state='succeeded',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
    UPDATE public.zasp_security_agent_runs SET version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
    INSERT INTO public.zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,plan_hash,step_id,action_key,input_digest,result_digest,receipt_kind,receipt_version,body)
     VALUES(o,w,e,r,rr.plan_hash,s,'create_temporary_policy',st.input_digest,result_hash,'temporary_policy_applied.v1',1,jsonb_build_object('deployment_id',deployment_id,'control_id',control_id,'control_version',1,'outcome_id',outcome_id,'applied_at',to_char(applied AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
   END IF;
  END IF;
  SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
  SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
  SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
  lease_until:=COALESCE(fx.lease_expires_at,prior_lease);
  targets:=zasp_sa_multistep_prior.application_targets(o,w,e,r,s);
  result_value:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'operation',op,'run_version',rr.version,'step_version',st.version,'effect_version',fx.version,'effect_state',fx.state,'attempt',fx.attempt,'reservation_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_reservation',r||chr(31)||s),'plan_hash','sha256:'||encode(rr.plan_hash,'hex'),'input_digest','sha256:'||encode(st.input_digest,'hex'),'ttl_seconds',ttl,'lease_expires_at',to_char(lease_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'targets',targets,'control_id',CASE WHEN op='complete' THEN control_id ELSE '' END,'deployment_id',COALESCE(deployment_id,''),'result_digest',COALESCE('sha256:'||encode(result_hash,'hex'),''));
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body)
   VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_application_'||op,request_digest,jsonb_build_object('contract_version',61,'request',request_value-'lease_token','lease_expires_at',to_char(lease_until AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'response',result_value));
 END IF;
 -- FK, sequence, target, control, receipt and audit writes can wait. All
 -- provisional changes abort when current authority or the issuing lease died.
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) OR NOT COALESCE(public.zasp_security_agent_action_principal_ready(),false)
  OR prior_lease IS NOT NULL AND prior_lease<=clock_timestamp() OR (result_value->>'lease_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application expired after wait';END IF;
 IF op='complete' THEN
  PERFORM zasp_sa_multistep_prior.deployment_verified(o,w,e,r,s);
  IF NOT zasp_sa_multistep_prior.application_ready(o,w,e,r) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered application receipt changed';END IF;
 END IF;
 RETURN result_value;
END $application$;

DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname IN('application_lock','application_current','application_source','application_policies','application_targets','application') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',p);
 END LOOP;
END $owners$;
GRANT USAGE ON SCHEMA zasp_sa_multistep_prior TO zasp_security_agent_action_worker;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.application(text,text,jsonb) TO zasp_security_agent_action_worker;
