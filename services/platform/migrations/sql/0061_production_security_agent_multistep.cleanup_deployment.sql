-- Reuse the reviewed private deployment composition/lease boundary, with an
-- explicit retained cleanup gate. No historical function or grant is changed.
DO $cores$
DECLARE d text;needle text;
BEGIN
 d:=pg_get_functiondef('zasp_sa_multistep_prior.deployment_composition(text,text,text,text)'::regprocedure);
 IF strpos(d,'expires timestamptz;')=0 OR strpos(d,'jsonb_array_length(temporary) NOT BETWEEN 1 AND 100')=0 OR strpos(d,'jsonb_array_length(policies) NOT BETWEEN 2 AND 100')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup composition predecessor rejected';END IF;
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.deployment_composition(o text, w text, e text, d text)','FUNCTION zasp_sa_multistep_prior.cleanup_composition(o text, w text, e text, d text, r text, s text)');
 d:=replace(d,'expires timestamptz;','expires timestamptz;cap timestamptz;');
 -- The marker authorizes five minutes of removal work; it is not the
 -- replacement bundle's lifetime. Anchor a stable 24-hour upper bound to
 -- its signed issue time, then retain every unrelated source's earlier cap.
 d:=replace(d,E'BEGIN\n',E'BEGIN\n SELECT issued_at+interval ''24 hours'' INTO STRICT cap FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,''cleanup'',d) AND state IN(''stored'',''verified'');\n expires:=cap;\n');
 d:=replace(d,'jsonb_array_length(temporary) NOT BETWEEN 1 AND 100','jsonb_array_length(temporary)>100');
 d:=replace(d,'jsonb_array_length(policies) NOT BETWEEN 2 AND 100','jsonb_array_length(policies)>100');
 d:=replace(d,'SELECT jsonb_agg(value ORDER BY (value->>''id'') COLLATE "C") INTO policies','SELECT COALESCE(jsonb_agg(value ORDER BY (value->>''id'') COLLATE "C"),''[]''::jsonb) INTO policies');
 d:=replace(d,'''persistent_sources'',persistent','''replacement_expires_at'',to_char(cap AT TIME ZONE ''UTC'',''YYYY-MM-DD"T"HH24:MI:SS.US"Z"''),''persistent_sources'',persistent');
 IF strpos(d,'FUNCTION zasp_sa_multistep_prior.cleanup_composition(')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup composition identity rejected';END IF;
 EXECUTE d;
 d:=pg_get_functiondef('zasp_sa_multistep_prior.deployment(text,text,jsonb)'::regprocedure);
 IF strpos(d,'zasp_sa_multistep_prior.application_current(o,w,e,r,s)')=0 OR strpos(d,'(o,w,e,r,s,''apply'',d)')=0 OR strpos(d,'target.policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup deployment predecessor rejected';END IF;
 d:=replace(d,'FUNCTION zasp_sa_multistep_prior.deployment(','FUNCTION zasp_sa_multistep_prior.cleanup_deployment(');
 d:=replace(d,'zasp_sa_multistep_prior.application_lock(o,w,e,r,d)','zasp_sa_multistep_prior.cleanup_lock(o,w,e,r,d)');
 d:=replace(d,'zasp_sa_multistep_prior.application_current(o,w,e,r,s)','zasp_sa_multistep_prior.cleanup_current(o,w,e,r,s)');
 d:=replace(d,'(o,w,e,r,s,''apply'',d)','(o,w,e,r,s,''cleanup'',d)');
 d:=replace(d,'target.policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()','target.policies IS DISTINCT FROM ''[]''::jsonb');
 d:=replace(d,'zasp_sa_multistep_prior.deployment_composition(o,w,e,d)','zasp_sa_multistep_prior.cleanup_composition(o,w,e,d,r,s)');
 d:=replace(replace(d,'security_agent_ordered_delivery','security_agent_ordered_cleanup_delivery'),'ordered_delivery_','ordered_cleanup_delivery_');
 IF strpos(d,'prior_lease timestamptz;')=0 OR strpos(d,'IF expires IS NULL OR expires<=clock_timestamp()')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup refresh predecessor rejected';END IF;
 d:=replace(d,'prior_lease timestamptz;','prior_lease timestamptz;refresh_clock timestamptz;');
 d:=replace(d,'IF expires IS NULL OR expires<=clock_timestamp()','IF expires IS NULL OR expires<=clock_timestamp()+interval ''1 minute''');
 needle:='composition:=zasp_sa_multistep_prior.cleanup_composition(o,w,e,d,r,s);';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup composition window predecessor rejected';END IF;
 d:=replace(d,needle,needle||E'\n IF (composition->>''expires_at'')::timestamptz<=clock_timestamp()+interval ''1 minute'' THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''ordered cleanup composition refresh window expired'';END IF;');
 needle:='SELECT COALESCE(max(sequence)+1,1) INTO sequence_value FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup recovery predecessor rejected';END IF;
 d:=replace(d,needle,E'SELECT * INTO bundle FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(o,w,e,d,work.leased_sequence);\n   IF FOUND THEN\n    IF work.leased_generation IS DISTINCT FROM target.desired_generation OR work.leased_credential_id IS DISTINCT FROM target.credential_id OR work.leased_input_digest IS DISTINCT FROM input_hash OR bundle.credential_id IS DISTINCT FROM target.credential_id OR bundle.policies IS DISTINCT FROM composition->''policies'' OR bundle.expires_at<=clock_timestamp() OR bundle.expires_at>(composition->>''expires_at'')::timestamptz OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,''ordered_cleanup_delivery_store'') AND a.body->''composition''=composition AND a.body->''request''->>''device_id''=d AND a.body->''request''->''sequence''=to_jsonb(bundle.sequence) AND a.body->''request''->>''digest''=''sha256:''||encode(bundle.envelope_digest,''hex'')) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''ordered retained cleanup bundle changed'';END IF;\n    sequence_value:=bundle.sequence;\n   ELSE\n    '||needle||E'\n   END IF;');
 -- This run's cleanup uses a sequence later than its fenced application claim.
 -- This is not a global reservation: other producers may reuse that sequence.
 d:=replace(d,needle,'SELECT COALESCE(max(sequence)+1,1) INTO sequence_value FROM (SELECT sequence FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d) UNION ALL SELECT (body->''work''->>''leased_sequence'')::bigint FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,''ordered_partial_deployment_handoff'') AND body->>''device_id''=d) retained_sequences;');
 needle:=E'   ELSE\n    SELECT * INTO bundle';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup finish predecessor rejected';END IF;
 d:=replace(d,needle,E'   ELSE\n    IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE a.organization_id=o AND a.audit_id=public.zasp_discovery_canonical_id(o,w,e,''security_agent_ordered_cleanup_delivery'',r||chr(31)||s||chr(31)||encode(digest(convert_to((request_value||jsonb_build_object(''operation'',''read'',''digest'',''''))::text,''UTF8''),''sha256''),''hex'')) AND a.event_kind=''ordered_cleanup_delivery_read'' AND a.body->''composition''=composition AND a.body->''work''=to_jsonb(work)-''lease_token'') THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''ordered cleanup read acknowledgement absent'';END IF;\n    SELECT * INTO bundle');
 needle:='IF bundle.policies IS DISTINCT FROM composition->''policies''';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup bundle evidence predecessor rejected';END IF;
 d:=replace(d,needle,'IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,''ordered_cleanup_delivery_read'') AND a.body->''request''=(request_value-ARRAY[''lease_token'',''action_lease_token''])||jsonb_build_object(''operation'',''read'',''digest'','''') AND a.body->''response''->''result''=zasp_sa_multistep_prior.cleanup_bundle_snapshot(bundle)) OR bundle.policies IS DISTINCT FROM composition->''policies''');
 needle:='result_value:=public.zasp_policy_deployment_finish(o,w,e,d,target.desired_generation,worker,token,decode(substring(request_value->>''digest'' FROM 8),''hex''));';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup finish refresh predecessor rejected';END IF;
 d:=replace(d,needle,needle||E'\n    refresh_clock:=clock_timestamp();\n    UPDATE public.zasp_policy_deployment_work SET available_at=LEAST(refresh_clock+interval ''12 hours'',bundle.expires_at-interval ''1 minute''),updated_at=refresh_clock WHERE (organization_id,workspace_id,environment_id,device_id,state,desired_generation,applied_generation)=(o,w,e,d,''scheduled'',target.desired_generation,target.desired_generation);\n    IF NOT zasp_sa_multistep_prior.cleanup_delivery_fresh(o,w,e,d) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''ordered cleanup refresh cannot precede expiry'';END IF;');
 needle:='RETURN response_value;';
 IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup final refresh predecessor rejected';END IF;
 d:=replace(d,needle,E'IF (composition->>''expires_at'')::timestamptz<=clock_timestamp()+interval ''1 minute'' OR op=''finish'' AND NOT zasp_sa_multistep_prior.cleanup_delivery_fresh(o,w,e,d) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''ordered cleanup refresh expired after wait'';END IF;\n '||needle);
 EXECUTE d;
END $cores$;

-- Match the unchanged granted read function's full signed envelope object.
-- A digest reference alone must not conceal changes to stored signed bytes.
CREATE FUNCTION zasp_sa_multistep_prior.cleanup_bundle_snapshot(b public.zasp_runtime_gateway_policy_bundles) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $bundle$
 SELECT jsonb_build_object('contract_version',b.contract_version,'key_id',b.key_id,'algorithm',b.algorithm,'audience',b.audience,'organization_id',b.organization_id,'workspace_id',b.workspace_id,'environment_id',b.environment_id,'device_id',b.device_id,'sequence',b.sequence,'policy_version',b.policy_version,'issued_at',to_char(b.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(b.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',b.failure_mode,'payload_digest',encode(b.payload_digest,'hex'),'policies',b.policies,'signature',replace(replace(replace(replace(trim(trailing '=' from encode(b.signature,'base64')),chr(10),''),chr(13),''),'+','-'),'/','_'))
$bundle$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_delivery_fresh(o text,w text,e text,d text) RETURNS boolean LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $fresh$
 SELECT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work x JOIN public.zasp_runtime_gateway_policy_bundles b ON(b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.applied_envelope_digest)
  WHERE (x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.state)=(o,w,e,d,'scheduled') AND x.applied_generation=x.desired_generation AND b.expires_at>clock_timestamp()+interval '1 minute' AND x.available_at>clock_timestamp() AND x.available_at<=b.expires_at-interval '1 minute' AND x.available_at<=x.updated_at+interval '12 hours')
$fresh$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_acknowledgements(o text,w text,e text,r text,s text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $acks$
DECLARE t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;a public.zasp_security_agent_temporary_policy_targets%ROWTYPE;b public.zasp_runtime_gateway_policy_bundles%ROWTYPE;
composition jsonb;result jsonb:='[]';ack jsonb;finish public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup')) IS DISTINCT FROM (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') AND state IN('stored','verified')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup target set changed';END IF;
 FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') ORDER BY device_id LOOP
  SELECT * INTO a FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'apply',t.device_id);
  IF t.state NOT IN('stored','verified') OR t.policies IS DISTINCT FROM '[]'::jsonb OR t.failure_mode<>'closed' OR t.expires_at<>t.issued_at+interval '5 minutes' OR t.desired_generation IS NULL OR a.device_id IS NULL OR t.credential_id<>a.credential_id
   OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,t.device_id,'active'))
   OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup target not acknowledged';END IF;
  composition:=zasp_sa_multistep_prior.cleanup_composition(o,w,e,t.device_id,r,s);
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(composition->'temporary_sources') x WHERE x->>'run_id'=r AND x->>'step_id'=s) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup source remains active';END IF;
  SELECT bundle.* INTO b FROM public.zasp_policy_deployment_work work JOIN public.zasp_runtime_gateway_policy_bundles bundle ON(bundle.organization_id,bundle.workspace_id,bundle.environment_id,bundle.device_id,bundle.envelope_digest)=(work.organization_id,work.workspace_id,work.environment_id,work.device_id,work.applied_envelope_digest)
   WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id,work.desired_generation,work.applied_generation,work.state)=(o,w,e,t.device_id,t.desired_generation,t.desired_generation,'scheduled') AND bundle.credential_id=t.credential_id AND bundle.policies=composition->'policies' AND bundle.failure_mode='closed' AND bundle.expires_at>clock_timestamp() AND bundle.expires_at<=(composition->>'expires_at')::timestamptz;
  IF NOT FOUND OR NOT zasp_sa_multistep_prior.cleanup_delivery_fresh(o,w,e,t.device_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup deployment incomplete';END IF;
  SELECT * INTO finish FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.event_kind)=(o,w,e,r,s,'ordered_cleanup_delivery_finish') AND x.body->'composition'=composition AND x.body->'request'->>'device_id'=t.device_id AND x.body->'request'->>'source_digest'='sha256:'||encode(t.envelope_digest,'hex') AND x.body->'request'->>'digest'='sha256:'||encode(b.envelope_digest,'hex') AND x.body->'request'->'sequence'=to_jsonb(b.sequence) AND x.body->'response'->'result'->>'state'='scheduled' AND x.body->'work'=(SELECT to_jsonb(work)-'lease_token' FROM public.zasp_policy_deployment_work work WHERE (work.organization_id,work.workspace_id,work.environment_id,work.device_id)=(o,w,e,t.device_id));
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.event_kind)=(o,w,e,r,s,'ordered_cleanup_delivery_read') AND x.body->'request'=finish.body->'request'||jsonb_build_object('operation','read','digest','') AND x.body->'composition'=composition AND x.body->'response'->'result'=zasp_sa_multistep_prior.cleanup_bundle_snapshot(b)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup finish evidence absent';END IF;
  ack:=jsonb_build_object('device_id',t.device_id,'credential_id',t.credential_id,'removed_source_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_source',concat_ws(chr(31),r,s,t.device_id,a.sequence::text,'sha256:'||encode(a.envelope_digest,'hex'))),'removed_source_digest','sha256:'||encode(a.envelope_digest,'hex'),'removed_sequence',a.sequence,'cleanup_source_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_source',concat_ws(chr(31),r,s,t.device_id,t.sequence::text,'sha256:'||encode(t.envelope_digest,'hex'))),'cleanup_source_digest','sha256:'||encode(t.envelope_digest,'hex'),'cleanup_sequence',t.sequence,'desired_generation',t.desired_generation,'deployment_sequence',b.sequence,'deployment_digest','sha256:'||encode(b.envelope_digest,'hex'),'composition_digest','sha256:'||encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(composition),'UTF8'),'sha256'),'hex'));
  result:=result||jsonb_build_array(ack||jsonb_build_object('acknowledgement_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_cleanup_acknowledgement',r||chr(31)||s||chr(31)||encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(ack),'UTF8'),'sha256'),'hex'))));
 END LOOP;
 IF jsonb_array_length(result) NOT BETWEEN 1 AND 100 OR octet_length(result::text)>120000 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup acknowledgement bound rejected';END IF;
 RETURN result;
END $acks$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname IN('cleanup_composition','cleanup_deployment','cleanup_bundle_snapshot','cleanup_delivery_fresh','cleanup_acknowledgements') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_policy_deployment_worker',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.cleanup_deployment(text,text,jsonb) TO zasp_policy_deployment_worker;
