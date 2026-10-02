-- Private ordered deployment boundary. Only claim is release61-specific; the
-- established store/read/finish functions still run as a deployment principal.
-- There is no bulk recovery selector and no public worker registration here.
-- Canonical JSON matches encoding/json after decoding into JSON values: sorted
-- object keys, preserved array order, no whitespace, and escaped HTML/runes.
CREATE FUNCTION zasp_sa_multistep_prior.deployment_json(v jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $json$
DECLARE result text;
BEGIN
 CASE jsonb_typeof(v)
 WHEN 'object' THEN SELECT '{'||COALESCE(string_agg(zasp_sa_multistep_prior.deployment_json(to_jsonb(key))||':'||zasp_sa_multistep_prior.deployment_json(value),',' ORDER BY key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(v);
 WHEN 'array' THEN SELECT '['||COALESCE(string_agg(zasp_sa_multistep_prior.deployment_json(value),',' ORDER BY ord),'')||']' INTO result FROM jsonb_array_elements(v) WITH ORDINALITY a(value,ord);
 WHEN 'string' THEN result:=replace(replace(replace(replace(replace(v::text,'<','\u003c'),'>','\u003e'),'&','\u0026'),chr(8232),'\u2028'),chr(8233),'\u2029');
 ELSE result:=v::text;
 END CASE;
 RETURN result;
END $json$;

-- Match the private Go wire limits: persistent provenance <5.4 MiB, the
-- signable compiled set <=1 MiB, temporary-source copies <=1 MiB, and bounded
-- source/claim metadata fit 8 MiB. Store adds one <=1 MiB canonical envelope;
-- 10 MiB also covers jsonb output spaces. Size the actual SQL response bytes.
CREATE FUNCTION zasp_sa_multistep_prior.deployment_wire(v jsonb,request_value boolean) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $wire$
 SELECT COALESCE(jsonb_typeof(v)='object' AND octet_length(v::text)<=CASE WHEN request_value THEN 10485760 ELSE 8388608 END,false)
$wire$;

-- Claim does not bind a signing key. Reserve its maximum legal 64-byte ID to
-- guarantee any configured key can fit the unchanged 1 MiB gateway contract.
-- Store checks the actual canonical envelope, key and signature separately.
CREATE FUNCTION zasp_sa_multistep_prior.deployment_signable(o text,w text,e text,d text,sequence_value bigint,policies jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $signable$
 SELECT octet_length(zasp_sa_multistep_prior.deployment_json(jsonb_build_object('contract_version',1,'key_id',repeat('k',64),'algorithm','Ed25519','audience','runtime-gateway-policy','organization_id',o,'workspace_id',w,'environment_id',e,'device_id',d,'sequence',sequence_value,'policy_version',sequence_value,'issued_at','2026-01-01T00:00:00Z','expires_at','2026-01-01T01:00:00Z','failure_mode','closed','payload_digest',repeat('0',64),'policies',policies,'signature',repeat('A',86))))<=1048576
$signable$;

-- Match policy.bounded, including strings.TrimSpace's Unicode whitespace.
CREATE FUNCTION zasp_sa_multistep_prior.deployment_bounded(v jsonb,maximum integer) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $bounded$
 SELECT COALESCE(jsonb_typeof(v)='string' AND octet_length(v#>>'{}') BETWEEN 1 AND maximum AND position(chr(10) in v#>>'{}')=0 AND position(chr(13) in v#>>'{}')=0
  AND v#>>'{}'=btrim(v#>>'{}',U&'\0009\000a\000b\000c\000d\0020\0085\00a0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200a\2028\2029\202f\205f\3000'),false)
$bounded$;

CREATE FUNCTION zasp_sa_multistep_prior.deployment_compile(p jsonb,persistent boolean) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $compile$
DECLARE trigger_value text;action_value text;conditions jsonb;c jsonb;rego text;
BEGIN
 IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR NOT zasp_sa_multistep_prior.deployment_bounded(p->'id',128)
  OR jsonb_typeof(p->'conditions') IS DISTINCT FROM 'array' OR jsonb_array_length(p->'conditions') NOT BETWEEN 1 AND 32 OR NOT COALESCE(p->>'action' IN('monitor','block'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered composition policy rejected';END IF;
 trigger_value:=p->>'trigger';action_value:=p->>'action';
 IF persistent THEN
  IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['id','name','scope','trigger','conditions','action','rollout','failure_mode']) OR NOT zasp_sa_multistep_prior.deployment_bounded(p->'name',256)
   OR p->>'scope' IS DISTINCT FROM 'environment' OR NOT COALESCE(trigger_value IN('tool','runtime','network','file','credential') AND p->>'rollout' IN('monitor','enforced') AND p->>'failure_mode' IN('open','closed'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered persistent policy rejected';END IF;
  IF p->>'rollout'='monitor' THEN action_value:='monitor';END IF;
 ELSE
  IF NOT zasp_sa_multistep_prior.closed(p,ARRAY['id','trigger','action','conditions','rego','digest']) OR NOT zasp_sa_multistep_prior.deployment_bounded(p->'trigger',64) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered temporary policy rejected';END IF;
 END IF;
 FOR c IN SELECT value FROM jsonb_array_elements(p->'conditions') LOOP
  IF NOT zasp_sa_multistep_prior.closed(c,ARRAY['field','operator','value']) OR NOT zasp_sa_multistep_prior.deployment_bounded(c->'field',128)
   OR jsonb_typeof(c->'value') IS DISTINCT FROM 'string' OR NOT COALESCE(c->>'operator' IN('equals','present'),false) OR c->>'operator'='present' AND c->>'value'<>'' OR c->>'operator'='equals' AND NOT zasp_sa_multistep_prior.deployment_bounded(c->'value',256)
   OR persistent AND (c->>'operator'<>'equals' OR c->>'field' NOT IN('action','resource','principal_id','agent_id','session_id','environment_id')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered policy condition rejected';END IF;
 END LOOP;
 IF persistent THEN
  IF trigger_value NOT IN('tool','runtime') THEN RETURN NULL;END IF;
  trigger_value:=CASE trigger_value WHEN 'tool' THEN 'tool_call' ELSE 'http_request' END;
 END IF;
 SELECT jsonb_agg(value ORDER BY (value->>'field') COLLATE "C",(value->>'value') COLLATE "C") INTO conditions FROM jsonb_array_elements(p->'conditions');
 rego:=E'package zasp.runtime\n\nimport rego.v1\n\npolicy_id := '||zasp_sa_multistep_prior.deployment_json(p->'id')||E'\ntrigger := '||zasp_sa_multistep_prior.deployment_json(to_jsonb(trigger_value))||E'\n\ndefault decision := {"action": "monitor", "matched": false}\n\ndecision := {"action": '||zasp_sa_multistep_prior.deployment_json(to_jsonb(action_value))||E', "matched": true} if {\n';
 FOR c IN SELECT value FROM jsonb_array_elements(conditions) LOOP
  rego:=rego||E'\tinput['||zasp_sa_multistep_prior.deployment_json(c->'field')||CASE WHEN c->>'operator'='present' THEN '] != ""' ELSE '] == '||zasp_sa_multistep_prior.deployment_json(c->'value') END||E'\n';
 END LOOP;
 rego:=rego||E'}\n';
 RETURN jsonb_build_object('id',p->>'id','trigger',trigger_value,'action',action_value,'conditions',conditions,'rego',rego,'digest',encode(digest(convert_to(rego,'UTF8'),'sha256'),'hex'));
END $compile$;

CREATE FUNCTION zasp_sa_multistep_prior.deployment_composition(o text,w text,e text,d text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $composition$
DECLARE persistent jsonb:='[]';temporary jsonb:='[]';policies jsonb:='[]';p record;t record;c jsonb;compiled jsonb;expires timestamptz;
BEGIN
 FOR p IN SELECT id,version,body FROM public.zasp_workflow_records WHERE (organization_id,workspace_id,environment_id,kind)=(o,w,e,'policy') AND deleted_at IS NULL AND body->>'rollout' IN('monitor','enforced') ORDER BY id COLLATE "C" LOOP
  IF p.body->>'id' IS DISTINCT FROM p.id THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered persistent identity changed';END IF;
  persistent:=persistent||jsonb_build_array(jsonb_build_object('id',p.id,'version',p.version,'policy',p.body));
  compiled:=zasp_sa_multistep_prior.deployment_compile(p.body,true);
  IF compiled IS NOT NULL THEN policies:=policies||jsonb_build_array(compiled);END IF;
 END LOOP;
 FOR t IN SELECT source.* FROM public.zasp_security_agent_temporary_policy_targets source WHERE (source.organization_id,source.workspace_id,source.environment_id,source.device_id,source.phase)=(o,w,e,d,'apply') AND source.state IN('stored','verified') AND source.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets c WHERE (c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.step_id,c.device_id,c.phase)=(o,w,e,source.run_id,source.step_id,d,'cleanup') AND c.state IN('stored','verified')) ORDER BY source.run_id COLLATE "C",source.step_id COLLATE "C" LOOP
  IF jsonb_typeof(t.policies) IS DISTINCT FROM 'array' OR jsonb_array_length(t.policies) NOT BETWEEN 1 AND 100 OR t.envelope_digest IS NULL OR t.desired_generation IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered temporary composition rejected';END IF;
  IF t.policies IS DISTINCT FROM (SELECT jsonb_agg(value ORDER BY (value->>'id') COLLATE "C") FROM jsonb_array_elements(t.policies)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered temporary policy order rejected';END IF;
  FOR c IN SELECT value FROM jsonb_array_elements(t.policies) LOOP
   IF c IS DISTINCT FROM zasp_sa_multistep_prior.deployment_compile(c,false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered temporary content changed';END IF;
   policies:=policies||jsonb_build_array(c);
  END LOOP;
  temporary:=temporary||jsonb_build_array(jsonb_build_object('source_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_source',concat_ws(chr(31),t.run_id,t.step_id,d,t.sequence::text,'sha256:'||encode(t.envelope_digest,'hex'))),'run_id',t.run_id,'step_id',t.step_id,'action_key',t.action_key,'credential_id',t.credential_id,'sequence',t.sequence,'policy_version',t.policy_version,'desired_generation',t.desired_generation,'envelope_digest','sha256:'||encode(t.envelope_digest,'hex'),'issued_at',to_char(t.issued_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'expires_at',to_char(t.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'failure_mode',t.failure_mode,'policies',t.policies));
  expires:=LEAST(expires,t.expires_at);
 END LOOP;
 IF jsonb_array_length(persistent)>100 OR jsonb_array_length(temporary) NOT BETWEEN 1 AND 100 OR jsonb_array_length(policies) NOT BETWEEN 2 AND 100 OR expires<=clock_timestamp()
  OR (SELECT count(*)<>count(DISTINCT value->>'id') FROM jsonb_array_elements(policies)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered composition bound or identity rejected';END IF;
 SELECT jsonb_agg(value ORDER BY (value->>'id') COLLATE "C") INTO policies FROM jsonb_array_elements(policies);
 RETURN jsonb_build_object('persistent_sources',persistent,'temporary_sources',temporary,'policies',policies,'expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END $composition$;

CREATE FUNCTION zasp_sa_multistep_prior.deployment_verified(o text,w text,e text,r text,s text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $verified$
DECLARE t record;composition jsonb;
BEGIN
 FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') ORDER BY device_id LOOP
  composition:=zasp_sa_multistep_prior.deployment_composition(o,w,e,t.device_id);
  IF NOT EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d JOIN public.zasp_runtime_gateway_policy_bundles b ON (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.envelope_digest)=(d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.applied_envelope_digest)
   WHERE (d.organization_id,d.workspace_id,d.environment_id,d.device_id,d.desired_generation,d.applied_generation)=(o,w,e,t.device_id,t.desired_generation,t.desired_generation) AND b.credential_id=t.credential_id AND b.failure_mode='closed' AND b.policies=composition->'policies' AND b.expires_at>=t.expires_at AND b.expires_at<=(composition->>'expires_at')::timestamptz AND b.expires_at>clock_timestamp()
    AND EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,'ordered_delivery_finish') AND a.body->'composition'=composition AND a.body->'request'->>'device_id'=t.device_id AND a.body->'request'->>'source_digest'='sha256:'||encode(t.envelope_digest,'hex') AND a.body->'request'->>'digest'='sha256:'||encode(b.envelope_digest,'hex') AND a.body->'request'->'sequence'=to_jsonb(b.sequence))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered acknowledged composition changed';END IF;
 END LOOP;
END $verified$;

CREATE FUNCTION zasp_sa_multistep_prior.deployment(checksum_value text,fingerprint_value text,request_value jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $deployment$
<<deploy_body>>
DECLARE o text;w text;e text;r text;s text;d text;op text;worker text;token text;key text;envelope jsonb;request_hash bytea;audit_id text;
 target public.zasp_security_agent_temporary_policy_targets%ROWTYPE;work public.zasp_policy_deployment_work%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 old_audit public.zasp_security_agent_audit%ROWTYPE;result_value jsonb;response_value jsonb;composition jsonb;expires timestamptz;sequence_value bigint;input_hash bytea;prior_lease timestamptz;bundle public.zasp_runtime_gateway_policy_bundles%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered deployment requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.deployment_wire(request_value,true) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment request wire budget exceeded';END IF;
 IF NOT zasp_sa_multistep_prior.closed(request_value,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','run_version','effect_version','action_worker_id','action_lease_token','device_id','credential_id','source_sequence','source_digest','desired_generation','operation','worker_id','lease_token','lease_seconds','sequence','input_digest','composition','envelope','digest']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment request rejected';END IF;
 FOREACH key IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','device_id','credential_id'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(request_value->>key),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment identity rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['run_version','effect_version','source_sequence','desired_generation','lease_seconds','sequence'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'number' OR (request_value->>key)!~'^(0|[1-9][0-9]{0,8})$' OR key<>'sequence' AND (request_value->>key)::bigint<1 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment version rejected';END IF;
 END LOOP;
 FOREACH key IN ARRAY ARRAY['worker_id','lease_token','action_worker_id','action_lease_token'] LOOP
  IF jsonb_typeof(request_value->key) IS DISTINCT FROM 'string' OR length(btrim(request_value->>key)) NOT BETWEEN 1 AND 128 OR (request_value->>key)~'[[:cntrl:]]' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment lease rejected';END IF;
 END LOOP;
 o:=request_value->>'organization_id';w:=request_value->>'workspace_id';e:=request_value->>'environment_id';r:=request_value->>'run_id';s:=request_value->>'step_id';d:=request_value->>'device_id';op:=request_value->>'operation';worker:=request_value->>'worker_id';token:=request_value->>'lease_token';envelope:=request_value->'envelope';
 IF NOT COALESCE(op IN('claim','store','read','finish'),false) OR length(token)<16 OR length(request_value->>'action_lease_token')<16 OR (request_value->>'lease_seconds')::integer NOT BETWEEN 30 AND 300 OR NOT COALESCE((request_value->>'source_digest')~'^sha256:[a-f0-9]{64}$',false)
  OR jsonb_typeof(envelope) IS DISTINCT FROM 'object' OR op<>'store' AND envelope<>'{}'::jsonb OR jsonb_typeof(request_value->'input_digest') IS DISTINCT FROM 'string' OR jsonb_typeof(request_value->'digest') IS DISTINCT FROM 'string'
  OR op='claim' AND ((request_value->>'sequence')::bigint<>0 OR request_value->>'input_digest'<>'' OR request_value->>'digest'<>'')
  OR op<>'claim' AND ((request_value->>'sequence')::bigint<1 OR NOT COALESCE((request_value->>'input_digest')~'^sha256:[a-f0-9]{64}$',false))
  OR op IN('store','finish') AND NOT COALESCE((request_value->>'digest')~'^sha256:[a-f0-9]{64}$',false) OR op='read' AND request_value->>'digest'<>'' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment operation rejected';END IF;
 IF NOT COALESCE(public.zasp_policy_deployment_principal_ready(),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered deployment principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered deployment release unavailable';END IF;
 PERFORM zasp_sa_multistep_prior.application_lock(o,w,e,r,d);
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 IF fx.state IS DISTINCT FROM 'leased' OR fx.version IS DISTINCT FROM (request_value->>'effect_version')::bigint OR fx.lease_owner IS DISTINCT FROM request_value->>'action_worker_id' OR fx.lease_token IS DISTINCT FROM request_value->>'action_lease_token' OR fx.lease_expires_at IS NULL OR fx.lease_expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id,version)=(o,w,e,r,(request_value->>'run_version')::bigint)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment action lease changed';END IF;
 SELECT * INTO target FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(o,w,e,r,s,'apply',d);
 IF target.state IS DISTINCT FROM 'stored' OR target.credential_id IS DISTINCT FROM request_value->>'credential_id' OR target.sequence IS DISTINCT FROM (request_value->>'source_sequence')::bigint OR target.policy_version IS DISTINCT FROM target.sequence OR target.desired_generation IS DISTINCT FROM (request_value->>'desired_generation')::bigint OR 'sha256:'||encode(target.envelope_digest,'hex') IS DISTINCT FROM request_value->>'source_digest' OR target.policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment source changed';END IF;
 SELECT * INTO work FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);
 IF work.device_id IS NULL OR work.desired_generation IS DISTINCT FROM target.desired_generation THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment work changed';END IF;
 composition:=zasp_sa_multistep_prior.deployment_composition(o,w,e,d);
 IF op='claim' AND request_value->'composition' IS DISTINCT FROM '{}'::jsonb OR op<>'claim' AND request_value->'composition' IS DISTINCT FROM composition THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered claimed composition changed';END IF;
 input_hash:=digest(convert_to(concat_ws(chr(31),o,w,e,r,s,d,target.credential_id,target.desired_generation::text,target.sequence::text,request_value->>'source_digest',zasp_sa_multistep_prior.deployment_json(composition)),'UTF8'),'sha256');
 request_hash:=digest(convert_to(request_value::text,'UTF8'),'sha256');
 audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_delivery',r||chr(31)||s||chr(31)||encode(request_hash,'hex'));
 response_value:=jsonb_build_object('contract_version',61,'run_id',r,'step_id',s,'operation',op,'source_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_source',concat_ws(chr(31),r,s,d,target.sequence::text,request_value->>'source_digest')),'work_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_work',concat_ws(chr(31),r,s,d,target.desired_generation::text)));
 SELECT a.* INTO old_audit FROM public.zasp_security_agent_audit a WHERE a.organization_id=o AND a.audit_id=deploy_body.audit_id FOR SHARE;
 IF FOUND THEN
  IF old_audit.event_digest IS DISTINCT FROM request_hash OR old_audit.body->'request' IS DISTINCT FROM request_value-ARRAY['lease_token','action_lease_token'] OR old_audit.body->'composition' IS DISTINCT FROM composition OR old_audit.body->'work' IS DISTINCT FROM to_jsonb(work)-'lease_token' OR (old_audit.body->>'lease_expires_at')::timestamptz<=clock_timestamp()
   OR op<>'finish' AND (work.state IS DISTINCT FROM 'leased' OR work.lease_token IS DISTINCT FROM token OR work.lease_owner IS DISTINCT FROM worker OR work.lease_expires_at IS NULL OR work.lease_expires_at<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment replay changed';END IF;
  response_value:=old_audit.body->'response';
 ELSE
  IF op='claim' THEN
   IF work.attempt>=100 OR work.applied_generation>=work.desired_generation OR work.state NOT IN('pending','retryable','leased') OR work.state='leased' AND (work.lease_expires_at>clock_timestamp() OR work.lease_token=token) OR work.state<>'leased' AND work.available_at>clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered scoped deployment lease unavailable';END IF;
   expires:=(composition->>'expires_at')::timestamptz;
   IF expires IS NULL OR expires<=clock_timestamp() OR jsonb_array_length(composition->'persistent_sources')+(SELECT COALESCE(sum(jsonb_array_length(value->'policies')),0) FROM jsonb_array_elements(composition->'temporary_sources'))>100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment composition unavailable';END IF;
   SELECT COALESCE(max(sequence)+1,1) INTO sequence_value FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);
   IF sequence_value NOT BETWEEN 1 AND 999999999 OR NOT zasp_sa_multistep_prior.deployment_signable(o,w,e,d,sequence_value,composition->'policies') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment composition cannot fit gateway envelope';END IF;
   prior_lease:=clock_timestamp()+make_interval(secs=>(request_value->>'lease_seconds')::integer);
   result_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'device_id',d,'credential_id',target.credential_id,'desired_generation',target.desired_generation,'sequence',sequence_value,'policy_version',sequence_value,'input_digest','sha256:'||encode(input_hash,'hex'),'lease_expires_at',to_char(prior_lease AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'composition',composition);
   IF NOT zasp_sa_multistep_prior.deployment_wire(response_value||jsonb_build_object('result',result_value),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment response wire budget exceeded';END IF;
   UPDATE public.zasp_policy_deployment_work SET state='leased',attempt=attempt+1,lease_owner=worker,lease_token=token,lease_expires_at=prior_lease,last_heartbeat_at=clock_timestamp(),leased_generation=target.desired_generation,leased_sequence=sequence_value,leased_policy_version=sequence_value,leased_credential_id=target.credential_id,leased_input_digest=input_hash,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d) RETURNING * INTO work;
  ELSE
   IF (work.state,work.lease_owner,work.lease_token,work.leased_generation,work.leased_sequence,work.leased_policy_version,work.leased_credential_id,work.leased_input_digest) IS DISTINCT FROM ('leased'::text,worker,token,target.desired_generation,(request_value->>'sequence')::bigint,(request_value->>'sequence')::bigint,target.credential_id,input_hash) OR work.lease_expires_at IS NULL OR work.lease_expires_at<=clock_timestamp() OR request_value->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(input_hash,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment lease lost';END IF;
   prior_lease:=work.lease_expires_at;
   IF op='store' THEN
    IF octet_length(zasp_sa_multistep_prior.deployment_json(envelope))>1048576 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment gateway envelope budget exceeded';END IF;
    IF NOT zasp_sa_multistep_prior.closed(envelope,ARRAY['contract_version','key_id','algorithm','audience','organization_id','workspace_id','environment_id','device_id','sequence','policy_version','issued_at','expires_at','failure_mode','payload_digest','policies','signature']) OR envelope->'contract_version' IS DISTINCT FROM '1'::jsonb OR envelope->>'algorithm' IS DISTINCT FROM 'Ed25519' OR envelope->>'audience' IS DISTINCT FROM 'runtime-gateway-policy' OR (envelope->>'organization_id',envelope->>'workspace_id',envelope->>'environment_id',envelope->>'device_id') IS DISTINCT FROM (o,w,e,d) OR envelope->'sequence' IS DISTINCT FROM to_jsonb(work.leased_sequence) OR envelope->'policy_version' IS DISTINCT FROM to_jsonb(work.leased_policy_version) OR envelope->>'failure_mode' IS DISTINCT FROM 'closed' OR envelope->'policies' IS DISTINCT FROM composition->'policies' OR (envelope->>'expires_at')::timestamptz>(composition->>'expires_at')::timestamptz OR (envelope->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered deployment envelope rejected';END IF;
    result_value:=public.zasp_policy_deployment_store(o,w,e,d,target.desired_generation,worker,token,target.credential_id,work.leased_sequence,work.leased_policy_version,envelope->>'key_id',(envelope->>'issued_at')::timestamptz,(envelope->>'expires_at')::timestamptz,envelope->>'failure_mode',decode(envelope->>'payload_digest','hex'),envelope->'policies',decode(translate(envelope->>'signature','-_','+/')||repeat('=',(4-length(envelope->>'signature')%4)%4),'base64'),decode(substring(request_value->>'digest' FROM 8),'hex'));
   ELSIF op='read' THEN
    result_value:=public.zasp_policy_deployment_read(o,w,e,d,work.leased_sequence);
    IF result_value->'policies' IS DISTINCT FROM composition->'policies' OR (result_value->>'expires_at')::timestamptz>(composition->>'expires_at')::timestamptz THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered read composition changed';END IF;
   ELSE
    SELECT * INTO bundle FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(o,w,e,d,work.leased_sequence);
    IF bundle.policies IS DISTINCT FROM composition->'policies' OR bundle.expires_at>(composition->>'expires_at')::timestamptz THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered finish composition changed';END IF;
    result_value:=public.zasp_policy_deployment_finish(o,w,e,d,target.desired_generation,worker,token,decode(substring(request_value->>'digest' FROM 8),'hex'));
    IF result_value->'desired_generation' IS DISTINCT FROM to_jsonb(target.desired_generation) OR result_value->'applied_generation' IS DISTINCT FROM to_jsonb(target.desired_generation) OR result_value->>'state' IS DISTINCT FROM 'scheduled' OR result_value->>'envelope_digest' IS DISTINCT FROM request_value->>'digest' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment finish changed';END IF;
   END IF;
  END IF;
  SELECT * INTO work FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,d);
  response_value:=jsonb_build_object('contract_version',61,'run_id',r,'step_id',s,'operation',op,'source_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_source',concat_ws(chr(31),r,s,d,target.sequence::text,request_value->>'source_digest')),'work_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_work',concat_ws(chr(31),r,s,d,target.desired_generation::text)),'result',result_value);
  IF NOT zasp_sa_multistep_prior.deployment_wire(response_value,false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment response wire budget exceeded';END IF;
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_delivery_'||op,request_hash,jsonb_build_object('request',request_value-ARRAY['lease_token','action_lease_token'],'composition',composition,'work',to_jsonb(work)-'lease_token','lease_expires_at',to_char(prior_lease AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'response',response_value));
 END IF;
 IF NOT zasp_sa_multistep_prior.deployment_wire(response_value,false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment replay wire budget exceeded';END IF;
 PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s);
 IF composition IS DISTINCT FROM zasp_sa_multistep_prior.deployment_composition(o,w,e,d) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered composition changed after wait';END IF;
 IF fx.lease_expires_at<=clock_timestamp() OR COALESCE(prior_lease,(old_audit.body->>'lease_expires_at')::timestamptz)<=clock_timestamp() OR NOT COALESCE(public.zasp_policy_deployment_principal_ready(),false) OR NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered deployment authority expired after wait';END IF;
 RETURN response_value;
END $deployment$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname IN('deployment_json','deployment_wire','deployment_signable','deployment_bounded','deployment_compile','deployment_composition','deployment_verified') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_policy_deployment_worker',p);
 END LOOP;
END $owners$;
ALTER FUNCTION zasp_sa_multistep_prior.deployment(text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.deployment(text,text,jsonb) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;
GRANT USAGE ON SCHEMA zasp_sa_multistep_prior TO zasp_policy_deployment_worker;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.deployment(text,text,jsonb) TO zasp_policy_deployment_worker;
