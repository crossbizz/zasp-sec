-- Retained safety authority, not a new action authorization. The original
-- applied and test receipts remain immutable and keep their existing keys.
CREATE TABLE zasp_sa_multistep_prior.cleanups(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 cleanup_id text NOT NULL,control_id text NOT NULL,reservation_id text NOT NULL,
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=262144),
 state text NOT NULL CHECK(state IN('leased','retryable','cleaned')),version bigint NOT NULL CHECK(version BETWEEN 1 AND 999999),attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 100),
 lease_owner text,lease_token text,lease_expires_at timestamptz,started_at timestamptz NOT NULL,completed_at timestamptz,
 reason text NOT NULL CHECK(reason IN('none','no_external_call','unknown_call','partial_acknowledgement','complete_unsettled')),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,cleanup_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id),
 CHECK((state='leased' AND lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL) OR (state<>'leased' AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL))
);
CREATE TABLE zasp_sa_multistep_prior.cleanup_receipts(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,step_id text NOT NULL,
 receipt_kind text NOT NULL CHECK(receipt_kind IN('temporary_policy_cleaned.v1','temporary_policy_partial_cleaned.v1')),
 body jsonb NOT NULL CHECK(octet_length(body::text)<=131072),digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES zasp_sa_multistep_prior.cleanups(organization_id,workspace_id,environment_id,run_id,step_id)
);
DO $tables$
DECLARE n text;
BEGIN
 FOREACH n IN ARRAY ARRAY['cleanups','cleanup_receipts'] LOOP
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_sa_multistep_prior.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_sa_multistep_prior.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('REVOKE ALL ON zasp_sa_multistep_prior.%I FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_policy_deployment_worker',n);
 END LOOP;
END $tables$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_sa_multistep_prior.cleanup_receipts FOR EACH STATEMENT EXECUTE FUNCTION zasp_sa_multistep_prior.immutable_admission();

-- At most 100 fixed-shape acknowledgements fit 120000 bytes; their receipt
-- fits 128 KiB, and receipt plus 100 target summaries fits 256 KiB. Cleanup
-- requests contain only one empty-policy source envelope and fit 32 KiB.
-- The separate full-composition delivery keeps its reviewed 8/10 MiB caps.
CREATE FUNCTION zasp_sa_multistep_prior.cleanup_wire(v jsonb,kind text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $wire$
 SELECT COALESCE(jsonb_typeof(v)='object' AND octet_length(v::text)<=CASE kind WHEN 'request' THEN 32768 WHEN 'response' THEN 262144 WHEN 'receipt' THEN 131072 END,false)
$wire$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_lock(o text,w text,e text,r text,d text DEFAULT NULL) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $lock$
BEGIN
 PERFORM zasp_sa_multistep_prior.application_lock(o,w,e,r,d);
 PERFORM 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_red_team_runs WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND run_id IN(SELECT test_run_id FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) ORDER BY run_id FOR SHARE NOWAIT;
 PERFORM 1 FROM public.zasp_security_agent_test_invocations WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND test_run_id IN(SELECT test_run_id FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) ORDER BY test_run_id,category FOR SHARE NOWAIT;
 PERFORM 1 FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) ORDER BY step_id FOR UPDATE;
END $lock$;

-- Partial application is removal authority, never application-success evidence.
-- Bind the immutable cancellation/blocked audit and the exact stored sources.
-- A planned target with no source is not removed or reported as removed.
CREATE FUNCTION zasp_sa_multistep_prior.cleanup_partial_handoff(o text,w text,e text,r text,s text,actor text) RETURNS void
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $handoff$
DECLARE t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;d public.zasp_policy_deployment_work%ROWTYPE;b public.zasp_runtime_gateway_policy_bundles%ROWTYPE;
 a public.zasp_security_agent_audit%ROWTYPE;c public.zasp_security_agent_audit%ROWTYPE;read_a public.zasp_security_agent_audit%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 evidence jsonb;refs jsonb;request_value jsonb;h bytea;handoff_id text;outcome text;
BEGIN
 -- Only the initial partial cleanup claim calls this, after cleanup_lock and
 -- exact terminal/source authority checks. All shared work/device locks are
 -- already held in the established Organization/run/step/device order.
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,state)=(o,w,e,r,s,'apply','stored') ORDER BY device_id LOOP
  SELECT * INTO d FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id);
  IF d.state<>'leased' THEN CONTINUE;END IF;
  IF d.lease_expires_at IS NULL OR d.lease_expires_at>clock_timestamp() OR d.leased_generation IS DISTINCT FROM t.desired_generation OR d.desired_generation<d.leased_generation OR d.leased_credential_id IS DISTINCT FROM t.credential_id OR d.leased_policy_version IS DISTINCT FROM d.leased_sequence
   OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,t.device_id,'active'))
   OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff lease changed';END IF;
  SELECT * INTO b FROM public.zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id,sequence)=(o,w,e,t.device_id,d.leased_sequence);
  SELECT * INTO a FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_delivery_store') AND body->'request'->>'device_id'=t.device_id AND body->'request'->'sequence'=to_jsonb(d.leased_sequence);
  SELECT * INTO c FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_delivery_claim') AND ((body->'work')-ARRAY['desired_generation','available_at','updated_at'])=(to_jsonb(d)-ARRAY['lease_token','desired_generation','available_at','updated_at']);
  IF c.audit_id IS NULL OR (c.body->'work'->>'desired_generation')::bigint<>d.leased_generation
   OR c.body->'request'->>'source_digest' IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex') OR c.body->'request'->'source_sequence' IS DISTINCT FROM to_jsonb(t.sequence)
   OR c.body->'request'->'desired_generation' IS DISTINCT FROM to_jsonb(t.desired_generation) OR c.body->'request'->>'credential_id' IS DISTINCT FROM t.credential_id
   OR c.body->'response'->'result'->'sequence' IS DISTINCT FROM to_jsonb(d.leased_sequence) OR c.body->'response'->'result'->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(d.leased_input_digest,'hex')
   OR c.body->'response'->'result'->'composition' IS DISTINCT FROM c.body->'composition'
   OR d.leased_input_digest IS DISTINCT FROM digest(convert_to(concat_ws(chr(31),o,w,e,r,s,t.device_id,t.credential_id,t.desired_generation::text,t.sequence::text,'sha256:'||encode(t.envelope_digest,'hex'),zasp_sa_multistep_prior.deployment_json(c.body->'composition')),'UTF8'),'sha256')
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_delivery_finish') AND body->'request'->>'device_id'=t.device_id AND body->'request'->'sequence'=to_jsonb(d.leased_sequence)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff claim changed';END IF;
  IF b.device_id IS NULL AND a.audit_id IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) AND event_kind IN('ordered_delivery_store','ordered_delivery_read','ordered_delivery_finish') AND body->'request'->>'device_id'=t.device_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial uncalled evidence changed';END IF;
   outcome:='no_external_call';
  ELSE
  IF b.device_id IS NULL OR a.audit_id IS NULL OR b.credential_id IS DISTINCT FROM t.credential_id OR b.policy_version IS DISTINCT FROM d.leased_policy_version
   OR ((a.body->'request'->'envelope')-ARRAY['issued_at','expires_at']) IS DISTINCT FROM (zasp_sa_multistep_prior.cleanup_bundle_snapshot(b)-ARRAY['issued_at','expires_at'])
   OR (a.body->'request'->'envelope'->>'issued_at')::timestamptz IS DISTINCT FROM b.issued_at OR (a.body->'request'->'envelope'->>'expires_at')::timestamptz IS DISTINCT FROM b.expires_at
   OR a.body->'request'->>'digest' IS DISTINCT FROM 'sha256:'||encode(b.envelope_digest,'hex')
   OR a.body->'request'->>'source_digest' IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex') OR a.body->'request'->'source_sequence' IS DISTINCT FROM to_jsonb(t.sequence)
   OR a.body->'request'->'desired_generation' IS DISTINCT FROM to_jsonb(t.desired_generation) OR a.body->'request'->>'credential_id' IS DISTINCT FROM t.credential_id
   OR a.body->'request'->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(d.leased_input_digest,'hex') OR a.body->'request'->'composition' IS DISTINCT FROM a.body->'composition'
   OR ((a.body->'work')-ARRAY['desired_generation','available_at','updated_at']) IS DISTINCT FROM (to_jsonb(d)-ARRAY['lease_token','desired_generation','available_at','updated_at'])
   OR (a.body->'work'->>'desired_generation')::bigint<>d.leased_generation
   OR d.leased_input_digest IS DISTINCT FROM digest(convert_to(concat_ws(chr(31),o,w,e,r,s,t.device_id,t.credential_id,t.desired_generation::text,t.sequence::text,'sha256:'||encode(t.envelope_digest,'hex'),zasp_sa_multistep_prior.deployment_json(a.body->'composition')),'UTF8'),'sha256')
   THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff stored evidence changed';END IF;
   outcome:='unknown_application_outcome';
  END IF;
  refs:='[]';
  FOR read_a IN SELECT * FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) AND (audit_id IN(a.audit_id,c.audit_id) OR event_kind='ordered_delivery_read' AND body->'request'->>'device_id'=t.device_id AND body->'request'->'sequence'=to_jsonb(d.leased_sequence)) ORDER BY audit_id LOOP
   request_value:=read_a.body->'request'||jsonb_build_object('lease_token',d.lease_token,'action_lease_token',fx.lease_token);
   h:=digest(convert_to(request_value::text,'UTF8'),'sha256');
   IF read_a.event_digest IS DISTINCT FROM h OR read_a.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_delivery',r||chr(31)||s||chr(31)||encode(h,'hex'))
    OR read_a.body->'work' IS DISTINCT FROM c.body->'work' OR read_a.body->'composition' IS DISTINCT FROM c.body->'composition'
    OR read_a.event_kind='ordered_delivery_read' AND (read_a.body->'request' IS DISTINCT FROM (a.body->'request')||jsonb_build_object('operation','read','envelope','{}'::jsonb,'digest','') OR read_a.body->'response'->'result' IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_bundle_snapshot(b)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff audit changed';END IF;
   refs:=refs||jsonb_build_array(jsonb_build_object('audit_id',read_a.audit_id,'event_digest',encode(read_a.event_digest,'hex'),'body_digest',encode(digest(convert_to(read_a.body::text,'UTF8'),'sha256'),'hex')));
  END LOOP;
  evidence:=jsonb_build_object('outcome',outcome,'device_id',t.device_id,'work',to_jsonb(d)-'lease_token','lease_token_digest',encode(digest(convert_to(d.lease_token,'UTF8'),'sha256'),'hex'),'bundle',CASE WHEN b.device_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(b) END,'audits',refs);
  h:=digest(convert_to(evidence::text,'UTF8'),'sha256');handoff_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_partial_handoff',r||chr(31)||s||chr(31)||t.device_id);
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,handoff_id,handoff_id,r,s,actor,'ordered_partial_deployment_handoff',h,evidence);
  -- This is not a finish acknowledgement or an application resend. Retain
  -- applied fields, the immutable old bundle/audits and uncertainty above.
  UPDATE public.zasp_policy_deployment_work SET state='pending',available_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_heartbeat_at=NULL,leased_generation=NULL,leased_sequence=NULL,leased_policy_version=NULL,leased_credential_id=NULL,leased_input_digest=NULL,updated_at=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,device_id,state,lease_owner,lease_token,lease_expires_at,leased_generation,leased_sequence,leased_credential_id,leased_input_digest)=(o,w,e,t.device_id,'leased',d.lease_owner,d.lease_token,d.lease_expires_at,d.leased_generation,d.leased_sequence,d.leased_credential_id,d.leased_input_digest) AND lease_expires_at<=clock_timestamp();
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff lease lost';END IF;
 END LOOP;
END $handoff$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_partial_snapshot(o text,w text,e text,r text,s text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $partial$
DECLARE proof public.zasp_security_agent_audit%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;targets jsonb;claim public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)
  AND event_kind IN('ordered_run_cancelled','ordered_step_ready') AND body->'response'->>'outcome'='blocked' AND body->'response'->>'run_state' IN('cancelled','needs_human')
  AND event_digest=digest(convert_to((body->'request')::text,'UTF8'),'sha256') ORDER BY created_at,audit_id LIMIT 1;
 SELECT * INTO claim FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_application_claim')
  AND body->'request'->>'effect_version'='0' AND body->'response'->>'effect_state'='leased' ORDER BY created_at,audit_id LIMIT 1;
 IF s IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0') OR proof.audit_id IS NULL OR claim.audit_id IS NULL
  OR fx.run_id IS NULL OR fx.state NOT IN('leased','cleanup_failed','cleaned') OR fx.result_digest IS NOT NULL OR fx.outcome_id IS NOT NULL
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('cancelled','needs_human') AND completed_at IS NOT NULL)
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,state,input_digest)=(o,w,e,r,s,0,'create_temporary_policy','executing',fx.input_digest))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index,state)=(o,w,e,r,1,'cancelled'))
  OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'create_temporary_policy',fx.input_digest))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,version)=(o,w,e,r,s,'approved',2) AND approver_id<>requester_id AND decided_at IS NOT NULL AND fresh_auth_at BETWEEN decided_at-interval '5 minutes' AND decided_at+interval '5 seconds')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial cleanup authority absent';END IF;
 IF (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply')) IS DISTINCT FROM jsonb_array_length(claim.body->'response'->'targets')
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.phase)=(o,w,e,r,'apply')
   AND (t.step_id<>s OR t.state NOT IN('planned','stored') OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(claim.body->'response'->'targets') x WHERE x->>'device_id'=t.device_id AND x->>'credential_id'=t.credential_id AND (x->>'sequence')::bigint=t.sequence)
    OR t.state='stored' AND (t.policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies() OR t.failure_mode<>'closed' OR t.envelope_digest IS NULL OR t.desired_generation IS NULL
     OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,'ordered_application_store')
      AND a.body->'request'->'envelope'->>'device_id'=t.device_id AND a.body->'request'->'envelope'->>'credential_id'=t.credential_id
      AND a.body->'request'->'envelope'->>'envelope_digest'='sha256:'||encode(t.envelope_digest,'hex') AND a.body->'request'->'envelope'->'policies'=t.policies
      AND a.body->'request'->'envelope'->>'key_id'=t.key_id AND a.body->'request'->'envelope'->>'payload_digest'='sha256:'||encode(t.payload_digest,'hex')
      AND a.body->'request'->'envelope'->>'failure_mode'=t.failure_mode AND (a.body->'request'->'envelope'->>'sequence')::bigint=t.sequence AND (a.body->'request'->'envelope'->>'policy_version')::bigint=t.policy_version
      AND EXISTS(SELECT 1 FROM jsonb_array_elements(a.body->'response'->'targets') x WHERE x->>'device_id'=t.device_id AND x->>'credential_id'=t.credential_id AND (x->>'sequence')::bigint=t.sequence AND (x->>'policy_version')::bigint=t.policy_version AND (x->>'desired_generation')::bigint=t.desired_generation AND x->>'state'='stored' AND x->>'envelope_digest'='sha256:'||encode(t.envelope_digest,'hex'))
      AND (a.body->'request'->'envelope'->>'issued_at')::timestamptz=t.issued_at AND (a.body->'request'->'envelope'->>'expires_at')::timestamptz=t.expires_at
      AND decode(a.body->'request'->'envelope'->>'signature','base64')=t.signature)))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial source evidence changed';END IF;
 SELECT jsonb_agg(to_jsonb(t) ORDER BY device_id) INTO targets FROM public.zasp_security_agent_temporary_policy_targets t WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase,state)=(o,w,e,r,s,'apply','stored');
 IF targets IS NULL OR jsonb_array_length(targets) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial source absent';END IF;
 -- Claim-only absence was proven under the device lock at handoff. Its sealed
 -- null-bundle audit is historical evidence, not a permanent sequence claim:
 -- another run can legitimately publish that sequence after the lease clears.
 -- Stored/read handoffs still require the exact original immutable bundle.
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_audit h WHERE (h.organization_id,h.workspace_id,h.environment_id,h.run_id,h.step_id,h.event_kind)=(o,w,e,r,s,'ordered_partial_deployment_handoff') AND (h.event_digest IS DISTINCT FROM digest(convert_to(h.body::text,'UTF8'),'sha256')
  OR CASE WHEN h.body->>'outcome'='no_external_call' THEN h.body->'bundle' IS DISTINCT FROM 'null'::jsonb WHEN h.body->>'outcome'='unknown_application_outcome' THEN h.body->'bundle' IS DISTINCT FROM (SELECT to_jsonb(b) FROM public.zasp_runtime_gateway_policy_bundles b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.sequence)=(o,w,e,h.body->>'device_id',(h.body->'work'->>'leased_sequence')::bigint)) ELSE true END
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(h.body->'audits') x WHERE NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.audit_id)=(o,w,e,r,s,x->>'audit_id') AND x->>'event_digest'=encode(a.event_digest,'hex') AND x->>'body_digest'=encode(digest(convert_to(a.body::text,'UTF8'),'sha256'),'hex'))))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial handoff evidence changed';END IF;
 RETURN jsonb_build_object('kind','partial','application',jsonb_build_object('claim_digest',encode(digest(convert_to(claim.body::text,'UTF8'),'sha256'),'hex'),'deployment_handoffs',(SELECT COALESCE(jsonb_agg(jsonb_build_object('audit_id',audit_id,'digest',encode(event_digest,'hex'),'outcome',body->>'outcome') ORDER BY audit_id),'[]'::jsonb) FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_partial_deployment_handoff'))),'control',jsonb_build_object('control_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_control',r||chr(31)||s),'version',0),'effect',jsonb_build_object('input_digest',encode(fx.input_digest,'hex')),'test',jsonb_build_object('audit_id',proof.audit_id,'event_digest',encode(proof.event_digest,'hex'),'body',proof.body),'targets',targets,'reservation',(SELECT to_jsonb(x) FROM public.zasp_security_agent_step_reservations x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)));
END $partial$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_snapshot(o text,w text,e text,r text,s text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $snapshot$
DECLARE receipt public.zasp_sa_multistep_receipts%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;c public.zasp_security_agent_controls%ROWTYPE;
 result_hash bytea;deployment_hash bytea;expires timestamptz;applied timestamptz;test_step text;proof jsonb;settled zasp_sa_multistep_prior.test_settlements%ROWTYPE;outcome text;
BEGIN
 -- Expired approval, cancelled parent and disabled execution do not revoke
 -- already-owned cleanup. Immutable admission/budget consumption still bind.
 PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
 SELECT * INTO receipt FROM public.zasp_sa_multistep_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id,receipt_kind)=(o,w,e,r,s,'temporary_policy_applied.v1');
 IF NOT FOUND THEN RETURN zasp_sa_multistep_prior.cleanup_partial_snapshot(o,w,e,r,s);END IF;
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 SELECT * INTO c FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id)=(o,w,e,r,s,receipt.body->>'control_id');
 SELECT digest(fx.input_digest||decode(string_agg(encode(envelope_digest,'hex'),'' ORDER BY device_id),'hex'),'sha256'),digest(convert_to(jsonb_agg(jsonb_build_array(device_id,credential_id,sequence,policy_version,desired_generation,encode(envelope_digest,'hex')) ORDER BY device_id)::text,'UTF8'),'sha256'),min(expires_at),max(verified_at)
  INTO result_hash,deployment_hash,expires,applied FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply');
 IF s IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,step_index,action_key,state)=(o,w,e,r,s,0,'create_temporary_policy','succeeded') AND input_digest=receipt.input_digest)
  OR receipt.run_id IS NULL OR fx.state NOT IN('cleanup_pending','leased','cleaned','cleanup_failed') OR fx.input_digest IS DISTINCT FROM receipt.input_digest OR receipt.result_digest IS DISTINCT FROM result_hash OR fx.result_digest IS DISTINCT FROM result_hash OR receipt.body->>'outcome_id' IS DISTINCT FROM fx.outcome_id
  OR receipt.body->>'control_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_control',r||chr(31)||s)
  OR receipt.body->>'deployment_id' IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_deployment',r||chr(31)||s||chr(31)||encode(deployment_hash,'hex'))
  OR receipt.body->>'applied_at' IS DISTINCT FROM to_char(applied AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') OR receipt.body->>'expires_at' IS DISTINCT FROM to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  OR c.state NOT IN('active','disabled') OR c.control_id IS NULL OR c.target_id IS DISTINCT FROM e OR c.action_key IS DISTINCT FROM 'create_temporary_policy' OR c.expires_at IS DISTINCT FROM expires OR c.version IS DISTINCT FROM ((receipt.body->>'control_version')::bigint+CASE WHEN c.state='disabled' THEN 1 ELSE 0 END)
  OR (SELECT count(*) FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))<>1
  OR (SELECT count(*) FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply')) NOT BETWEEN 1 AND 100
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,phase)=(o,w,e,r,'apply') AND (step_id<>s OR state<>'verified' OR verified_at IS NULL OR desired_generation IS NULL OR policies IS DISTINCT FROM zasp_sa_multistep_prior.application_policies()))
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,version)=(o,w,e,r,s,'approved',2) AND approver_id IS NOT NULL AND approver_id<>requester_id AND fresh_auth_at IS NOT NULL AND decided_at IS NOT NULL AND fresh_auth_at>=decided_at-interval '5 minutes' AND fresh_auth_at<=decided_at+interval '5 seconds')
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_step_reservations WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest)=(o,w,e,r,s,'create_temporary_policy',receipt.input_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered retained application evidence changed';END IF;
 SELECT step_id INTO test_step FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index,action_key)=(o,w,e,r,1,'run_test');
 SELECT * INTO settled FROM zasp_sa_multistep_prior.test_settlements WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step);
 IF FOUND THEN
  IF settled.snapshot IS DISTINCT FROM zasp_sa_multistep_prior.test_snapshot(o,w,e,r,test_step,settled.input_manifest,settled.output_manifest)
   OR NOT EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.receipt_kind)=(o,w,e,r,test_step,'existing_test_settled.v1') AND x.body=settled.response->'receipt' AND x.result_digest=decode(substr(settled.response->>'result_digest',8),'hex') AND x.body->>'snapshot_digest'=encode(digest(convert_to(settled.snapshot::text,'UTF8'),'sha256'),'hex'))
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,state,version)=(o,w,e,r,test_step,'succeeded',(settled.response->>'step_version')::bigint))
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,state,version)=(o,w,e,r,test_step,'run_test','verified',(settled.response->>'effect_version')::bigint) AND result_digest=decode(substr(settled.response->>'result_digest',8),'hex') AND outcome_id=settled.response->'receipt'->>'invocation_id' AND lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_test_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id,reconcile_state,reconcile_version)=(o,w,e,r,test_step,'settled',2) AND reconcile_worker IS NULL AND reconcile_token IS NULL AND reconcile_expires_at IS NULL AND reconcile_settlement=settled.response) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered retained settlement changed';END IF;
  proof:=jsonb_build_object('kind','existing_test_settled.v1','receipt',(SELECT to_jsonb(x) FROM public.zasp_sa_multistep_receipts x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step)),'settlement_digest',encode(digest(convert_to(to_jsonb(settled)::text,'UTF8'),'sha256'),'hex'));
 ELSE
  SELECT jsonb_build_object('kind',event_kind,'audit_id',audit_id,'digest',encode(event_digest,'hex'),'snapshot_digest',encode(digest(convert_to((body->'snapshot')::text,'UTF8'),'sha256'),'hex')) INTO proof FROM public.zasp_security_agent_audit a WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step) AND event_kind IN('ordered_test_uncertain','ordered_test_expired') AND event_digest=digest(convert_to(body::text,'UTF8'),'sha256') AND body->'snapshot'=zasp_sa_multistep_prior.test_snapshot(o,w,e,r,test_step,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step)),NULL)
   AND EXISTS(SELECT 1 FROM public.zasp_security_agent_steps x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.state,x.version)=(o,w,e,r,test_step,'inconclusive',(a.body->'response'->>'step_version')::bigint))
   AND EXISTS(SELECT 1 FROM public.zasp_security_agent_effects x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.action_key,x.state,x.version)=(o,w,e,r,test_step,'run_test','unknown_outcome',(a.body->'response'->>'effect_version')::bigint) AND x.result_digest IS NULL AND x.outcome_id IS NULL AND x.lease_owner IS NULL AND x.lease_token IS NULL AND x.lease_expires_at IS NULL);
  IF proof IS NULL THEN
   IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('cancelled','needs_human','failed','inconclusive')) OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step) AND state IN('cancelled','failed','inconclusive','executing')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup predecessor not terminal';END IF;
   -- Cancelled children may still retain a worker credential. Bind their exact
   -- snapshot by digest without copying that credential into cleanup evidence.
   SELECT jsonb_build_object('kind',event_kind,'audit_id',audit_id,'event_digest',encode(event_digest,'hex'),'step',(SELECT to_jsonb(x) FROM public.zasp_security_agent_steps x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step)),'test_snapshot_digest',encode(digest(convert_to(zasp_sa_multistep_prior.test_snapshot(o,w,e,r,test_step,(SELECT manifest FROM zasp_sa_multistep_prior.test_inputs WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,test_step)),NULL)::text,'UTF8'),'sha256'),'hex')) INTO proof FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND event_kind IN('ordered_run_cancelled','ordered_step_ready','ordered_approval_decided') AND body->'response'->>'outcome'='blocked' AND body->'response'->>'run_state' IN('cancelled','needs_human') AND event_digest=digest(convert_to((body->'request')::text,'UTF8'),'sha256') ORDER BY created_at DESC,audit_id DESC LIMIT 1;
   IF proof IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup terminal audit absent';END IF;
  END IF;
 END IF;
 RETURN jsonb_build_object('application',to_jsonb(receipt),'effect',jsonb_build_object('input_digest',encode(fx.input_digest,'hex'),'outcome_id',fx.outcome_id,'result_digest',encode(fx.result_digest,'hex')),'control',jsonb_build_object('control_id',c.control_id,'expires_at',c.expires_at,'version',receipt.body->'control_version'),'targets',(SELECT jsonb_agg(to_jsonb(x) ORDER BY device_id) FROM public.zasp_security_agent_temporary_policy_targets x WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply')),'test',proof,'reservation',(SELECT to_jsonb(x) FROM public.zasp_security_agent_step_reservations x WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)));
END $snapshot$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_targets(o text,w text,e text,r text,s text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $targets$
DECLARE result jsonb;
BEGIN
 IF EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') AND (sequence NOT BETWEEN 1 AND 999999999 OR policy_version<>sequence OR state='planned' AND (desired_generation IS NOT NULL OR envelope_digest IS NOT NULL) OR state<>'planned' AND (desired_generation IS NULL OR desired_generation NOT BETWEEN 1 AND 999999999 OR envelope_digest IS NULL))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup target wire authority rejected';END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('device_id',device_id,'credential_id',credential_id,'sequence',sequence,'policy_version',policy_version,'state',state,'desired_generation',COALESCE(desired_generation,0),'envelope_digest',COALESCE('sha256:'||encode(envelope_digest,'hex'),'')) ORDER BY device_id),'[]'::jsonb) INTO result FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup');
 IF jsonb_array_length(result) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup target count rejected';END IF;
 RETURN result;
END
$targets$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_current(o text,w text,e text,r text,s text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $current$
DECLARE c zasp_sa_multistep_prior.cleanups%ROWTYPE;
BEGIN
 SELECT * INTO c FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF c.run_id IS NULL OR c.snapshot IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_snapshot(o,w,e,r,s)
  OR c.state<>'leased' OR c.lease_expires_at<=clock_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,state,lease_owner,lease_token,lease_expires_at)=(o,w,e,r,s,'create_temporary_policy','leased',c.lease_owner,c.lease_token,c.lease_expires_at))
  OR c.snapshot->>'kind' IS DISTINCT FROM 'partial' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id,state)=(o,w,e,r,s,c.control_id,'active'))
  OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=(o,w,e,r,s,'cleanup')
   AND (NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.phase,a.device_id,a.credential_id)=(o,w,e,r,s,'apply',t.device_id,t.credential_id))
    OR NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices d WHERE (d.organization_id,d.workspace_id,d.environment_id,d.id,d.state)=(o,w,e,t.device_id,'active'))
    OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1)
    OR t.state<>'planned' AND (t.policies IS DISTINCT FROM '[]'::jsonb OR t.failure_mode<>'closed' OR t.expires_at<>t.issued_at+interval '5 minutes' OR t.expires_at<=clock_timestamp() OR t.desired_generation IS NULL))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered current cleanup authority unavailable';END IF;
END $current$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup_remediation_ready(o text,w text,e text,r text,snapshot_value jsonb) RETURNS boolean LANGUAGE sql VOLATILE SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(snapshot_value->'test'->'receipt'->'body'->>'outcome'='not_reproduced' AND (snapshot_value->'application'->'body'->>'expires_at')::timestamptz>clock_timestamp()
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND stop_reason IS NULL)
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=('*','*','*','*',true))
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(o,w,e,'*',true))
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(o,w,e,'create_temporary_policy',true))
  AND EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key,execution_enabled)=(o,w,e,'run_test',true)),false)
$ready$;

CREATE FUNCTION zasp_sa_multistep_prior.cleanup(checksum_value text,fingerprint_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $cleanup$
<<cleanup_body>>
DECLARE o text;w text;e text;r text;s text;op text;k text;worker text;token text;rv bigint;ev bigint;cv bigint;
 rr public.zasp_security_agent_runs%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;c zasp_sa_multistep_prior.cleanups%ROWTYPE;
snapshot_value jsonb;response jsonb;old_audit public.zasp_security_agent_audit%ROWTYPE;request_hash bytea;audit_id text;deadline timestamptz;original_deadline timestamptz;marker_deadline timestamptz;env jsonb;target record;receipt_body jsonb;receipt_digest bytea;acks jsonb;next_state text;ack_count integer;target_count integer;recovery_evidence jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered cleanup requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','operation','worker_id','lease_token','run_version','effect_version','version','lease_seconds','envelope']) OR NOT zasp_sa_multistep_prior.cleanup_wire(q,'request') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered cleanup input rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id','step_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered cleanup identity rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['run_version','effect_version','version','lease_seconds'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'number' OR NOT COALESCE(q->>k~'^(0|[1-9][0-9]{0,5})$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered cleanup version rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';s:=q->>'step_id';op:=q->>'operation';worker:=q->>'worker_id';token:=q->>'lease_token';rv:=(q->>'run_version')::bigint;ev:=(q->>'effect_version')::bigint;cv:=(q->>'version')::bigint;
 IF NOT COALESCE(op IN('claim','heartbeat','store','complete','reconcile') AND rv BETWEEN 1 AND 999998 AND ev BETWEEN 1 AND 999998 AND cv<999999 AND (q->>'lease_seconds')::integer BETWEEN 30 AND 300 AND jsonb_typeof(q->'worker_id')='string' AND length(btrim(worker)) BETWEEN 1 AND 128 AND worker!~'[[:cntrl:]]' AND jsonb_typeof(q->'lease_token')='string' AND length(token) BETWEEN 16 AND 128 AND token!~'[[:cntrl:]]' AND jsonb_typeof(q->'envelope')='object' AND (op='store' OR q->'envelope'='{}'::jsonb),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered cleanup operation rejected';END IF;
 IF NOT COALESCE(public.zasp_security_agent_action_principal_ready(),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered cleanup principal rejected';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered cleanup release unavailable';END IF;
 PERFORM zasp_sa_multistep_prior.cleanup_lock(o,w,e,r);
 snapshot_value:=zasp_sa_multistep_prior.cleanup_snapshot(o,w,e,r,s);
 IF octet_length(snapshot_value::text)>262144 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup snapshot budget exceeded';END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy');
 SELECT * INTO c FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 original_deadline:=c.lease_expires_at;
 IF c.run_id IS NOT NULL THEN
  IF c.snapshot IS DISTINCT FROM snapshot_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup retained authority changed';END IF;
  PERFORM zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,s);
 END IF;
 request_hash:=digest(convert_to(q::text,'UTF8'),'sha256');audit_id:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_cleanup_operation',r||chr(31)||s||chr(31)||encode(request_hash,'hex'));
 SELECT * INTO old_audit FROM public.zasp_security_agent_audit a WHERE a.organization_id=o AND a.audit_id=cleanup_body.audit_id;
 IF FOUND THEN
  response:=old_audit.body->'response';
  IF old_audit.event_digest IS DISTINCT FROM request_hash OR old_audit.body->'request' IS DISTINCT FROM q-'lease_token' OR old_audit.body->'owner' IS DISTINCT FROM to_jsonb(c)-'lease_token' OR response->'run_version' IS DISTINCT FROM to_jsonb(rr.version) OR response->>'run_state' IS DISTINCT FROM rr.state OR response->'effect_version' IS DISTINCT FROM to_jsonb(fx.version) OR response->>'effect_state' IS DISTINCT FROM fx.state OR response->'targets' IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,s)
   OR op NOT IN('complete','reconcile') AND (c.state<>'leased' OR c.lease_owner IS DISTINCT FROM worker OR c.lease_token IS DISTINCT FROM token OR c.lease_expires_at<=clock_timestamp())
   OR op='reconcile' AND (c.state<>'retryable' OR fx.state<>'cleanup_failed' OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup replay changed';END IF;
  IF op='complete' THEN
   SELECT body,digest INTO receipt_body,receipt_digest FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
   IF c.state<>'cleaned' OR fx.state<>'cleaned' OR receipt_body IS DISTINCT FROM response->'receipt' OR receipt_digest IS DISTINCT FROM digest(convert_to(zasp_sa_multistep_prior.deployment_json(receipt_body),'UTF8'),'sha256') OR c.snapshot->>'kind' IS DISTINCT FROM 'partial' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_controls WHERE (organization_id,workspace_id,environment_id,run_id,step_id,control_id,state)=(o,w,e,r,s,c.control_id,'disabled')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleaned evidence changed';END IF;
  END IF;
 ELSE
  IF rr.version<>rv OR fx.version<>ev OR COALESCE(c.version,0)<>cv OR rr.state NOT IN('contained','needs_human','cancelled','failed','inconclusive') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup version unavailable';END IF;
  deadline:=clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer);
  IF op='claim' THEN
   IF c.run_id IS NOT NULL THEN
    IF c.state<>'retryable' OR fx.state<>'cleanup_failed' OR c.attempt>=100 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') AND state<>'planned' AND expires_at<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup recovery unavailable';END IF;
    UPDATE zasp_sa_multistep_prior.cleanups SET state='leased',version=version+1,attempt=attempt+1,lease_owner=worker,lease_token=token,lease_expires_at=deadline,reason='none' WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING * INTO c;
   ELSE
   IF snapshot_value->>'kind'='partial' THEN
    IF fx.state<>'leased' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial cleanup claim unavailable';END IF;
    -- Cancellation has fenced application writes. Do not replace any active
    -- deployment owner; its exact expired outcome must remain recoverable.
    IF EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work d JOIN public.zasp_security_agent_temporary_policy_targets t USING(organization_id,workspace_id,environment_id,device_id) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=(o,w,e,r,s,'apply') AND d.state='leased' AND d.lease_expires_at>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered partial deployment still owned';END IF;
    PERFORM zasp_sa_multistep_prior.cleanup_partial_handoff(o,w,e,r,s,worker);
    snapshot_value:=zasp_sa_multistep_prior.cleanup_partial_snapshot(o,w,e,r,s);
   ELSIF fx.state<>'cleanup_pending' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup claim unavailable';END IF;
   -- Source-sequence admission is locked by application_lock. Prove the next
   -- trigger-assigned value fits the closed wire before reserving cleanup.
   IF EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.phase)=(o,w,e,r,s,'apply') AND (EXISTS(SELECT 1 FROM public.zasp_security_agent_temporary_policy_targets x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.device_id)=(o,w,e,a.device_id) AND x.sequence>=999999999) OR EXISTS(SELECT 1 FROM public.zasp_runtime_gateway_policy_bundles x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.device_id)=(o,w,e,a.device_id) AND x.sequence>=999999999))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup source sequence exhausted';END IF;
  INSERT INTO zasp_sa_multistep_prior.cleanups(organization_id,workspace_id,environment_id,run_id,step_id,cleanup_id,control_id,reservation_id,snapshot,state,version,attempt,lease_owner,lease_token,lease_expires_at,started_at,reason)
   VALUES(o,w,e,r,s,public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_cleanup',r||chr(31)||s),snapshot_value->'control'->>'control_id',public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_cleanup_reservation',r||chr(31)||s),snapshot_value,'leased',1,1,worker,token,deadline,clock_timestamp(),'none') RETURNING * INTO c;
   FOR target IN SELECT device_id,credential_id FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'apply') AND state IN('stored','verified') ORDER BY device_id LOOP
    INSERT INTO public.zasp_security_agent_temporary_policy_targets(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id,credential_id,sequence,policy_version) VALUES(o,w,e,r,s,'cleanup',target.device_id,target.credential_id,1,1);
   END LOOP;
   END IF;
  ELSIF op='reconcile' THEN
   IF c.state IS DISTINCT FROM 'leased' OR c.lease_expires_at IS NULL OR c.lease_expires_at>clock_timestamp() OR fx.state<>'leased' OR fx.lease_expires_at IS DISTINCT FROM c.lease_expires_at OR fx.lease_owner IS DISTINCT FROM c.lease_owner OR fx.lease_token IS DISTINCT FROM c.lease_token
    OR EXISTS(SELECT 1 FROM public.zasp_policy_deployment_work x JOIN public.zasp_security_agent_temporary_policy_targets t ON(t.organization_id,t.workspace_id,t.environment_id,t.device_id,t.desired_generation)=(x.organization_id,x.workspace_id,x.environment_id,x.device_id,x.leased_generation) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=(o,w,e,r,s,'cleanup') AND x.state='leased' AND x.lease_expires_at>clock_timestamp())
    OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup expiry not ready';END IF;
   SELECT count(*),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.step_id,a.event_kind)=(o,w,e,r,s,'ordered_cleanup_delivery_finish') AND a.body->'request'->>'device_id'=t.device_id AND a.body->'request'->>'source_digest'='sha256:'||encode(t.envelope_digest,'hex'))) INTO target_count,ack_count FROM public.zasp_security_agent_temporary_policy_targets t WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup');
   IF target_count NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup recovery target set absent';END IF;
   c.reason:=CASE WHEN ack_count=target_count THEN 'complete_unsettled' WHEN ack_count>0 THEN 'partial_acknowledgement' WHEN EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s,'ordered_cleanup_delivery_store')) THEN 'unknown_call' ELSE 'no_external_call' END;
   recovery_evidence:=jsonb_build_object('reason',c.reason,'acknowledged',ack_count,'targets',target_count,'snapshot_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value),'UTF8'),'sha256'),'hex'),'deployment_state',(SELECT jsonb_agg(jsonb_build_object('device_id',t.device_id,'target_digest',encode(digest(convert_to(to_jsonb(t)::text,'UTF8'),'sha256'),'hex'),'work_digest',encode(digest(convert_to((to_jsonb(x)-'lease_token')::text,'UTF8'),'sha256'),'hex')) ORDER BY t.device_id) FROM public.zasp_security_agent_temporary_policy_targets t LEFT JOIN public.zasp_policy_deployment_work x USING(organization_id,workspace_id,environment_id,device_id) WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,t.phase)=(o,w,e,r,s,'cleanup')));
   UPDATE zasp_sa_multistep_prior.cleanups SET state='retryable',version=version+1,reason=c.reason,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING * INTO c;
   UPDATE public.zasp_security_agent_runs SET state=CASE WHEN state='cancelled' THEN 'cancelled' ELSE 'needs_human' END,version=version+1,updated_at=clock_timestamp(),completed_at=COALESCE(completed_at,clock_timestamp()),last_error_code=CASE WHEN state='cancelled' THEN last_error_code ELSE 'cleanup_incomplete' END WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO rr;
  ELSE
   PERFORM zasp_sa_multistep_prior.cleanup_current(o,w,e,r,s);
   IF c.lease_owner IS DISTINCT FROM worker OR c.lease_token IS DISTINCT FROM token OR fx.lease_owner IS DISTINCT FROM worker OR fx.lease_token IS DISTINCT FROM token THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup lease changed';END IF;
   deadline:=c.lease_expires_at;
   IF op='heartbeat' THEN deadline:=clock_timestamp()+make_interval(secs=>(q->>'lease_seconds')::integer);
   ELSIF op='store' THEN
    env:=q->'envelope';
    IF NOT zasp_sa_multistep_prior.closed(env,ARRAY['device_id','credential_id','sequence','policy_version','key_id','issued_at','expires_at','failure_mode','payload_digest','policies','signature','envelope_digest']) OR env->'policies' IS DISTINCT FROM '[]'::jsonb OR env->>'failure_mode' IS DISTINCT FROM 'closed' OR NOT COALESCE(env->>'payload_digest'~'^sha256:[a-f0-9]{64}$' AND env->>'envelope_digest'~'^sha256:[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered cleanup source rejected';END IF;
    PERFORM zasp_sa_multistep_prior.application_source(o,w,e,r,s,'cleanup',worker,token,env->>'device_id',env->>'credential_id',(env->>'sequence')::bigint,(env->>'policy_version')::bigint,env->>'key_id',(env->>'issued_at')::timestamptz,(env->>'expires_at')::timestamptz,env->>'failure_mode',decode(substr(env->>'payload_digest',8),'hex'),env->'policies',decode(env->>'signature','base64'),decode(substr(env->>'envelope_digest',8),'hex'));
   ELSE
    -- First completion still consumes the signed execution markers. Save the
    -- earliest deadline before mutation; durable replay uses its saved proof.
    SELECT min(expires_at) INTO marker_deadline FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup');
    acks:=zasp_sa_multistep_prior.cleanup_acknowledgements(o,w,e,r,s);
    UPDATE public.zasp_security_agent_temporary_policy_targets SET state='verified',verified_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s,'cleanup') AND state='stored';
    next_state:=CASE WHEN rr.state='cancelled' THEN 'cancelled' WHEN rr.state='contained' AND zasp_sa_multistep_prior.cleanup_remediation_ready(o,w,e,r,snapshot_value) THEN 'remediated' ELSE 'needs_human' END;
    receipt_body:=jsonb_build_object('cleanup_id',c.cleanup_id,'control_id',c.control_id,'control_version',(snapshot_value->'control'->>'version')::bigint+1,'effect_id',snapshot_value->'effect'->>'outcome_id','application_receipt_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'application'),'UTF8'),'sha256'),'hex'),'test_evidence_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'test'),'UTF8'),'sha256'),'hex'),'removed_source_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'targets'),'UTF8'),'sha256'),'hex'),'cleanup_deployment_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(acks),'UTF8'),'sha256'),'hex'),'targets',acks,'started_at',to_char(c.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'attempts',c.attempt,'outcome','cleaned');
    IF snapshot_value->>'kind'='partial' THEN
     receipt_body:=(receipt_body-ARRAY['control_id','control_version','effect_id','application_receipt_digest','test_evidence_digest'])||jsonb_build_object('partial_application_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'application'),'UTF8'),'sha256'),'hex'),'cancellation_evidence_digest',encode(digest(convert_to(zasp_sa_multistep_prior.deployment_json(snapshot_value->'test'),'UTF8'),'sha256'),'hex'));
    END IF;
    IF NOT zasp_sa_multistep_prior.cleanup_wire(receipt_body,'receipt') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup evidence budget exceeded';END IF;
    receipt_digest:=digest(convert_to(zasp_sa_multistep_prior.deployment_json(receipt_body),'UTF8'),'sha256');
    INSERT INTO zasp_sa_multistep_prior.cleanup_receipts VALUES(o,w,e,r,s,CASE WHEN snapshot_value->>'kind'='partial' THEN 'temporary_policy_partial_cleaned.v1' ELSE 'temporary_policy_cleaned.v1' END,receipt_body,receipt_digest);
    UPDATE public.zasp_security_agent_controls SET state='disabled',version=version+1,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,control_id,state)=(o,w,e,c.control_id,'active');
    UPDATE public.zasp_security_agent_runs SET state=next_state,version=version+1,updated_at=clock_timestamp(),completed_at=COALESCE(completed_at,clock_timestamp()),last_error_code=CASE WHEN next_state='needs_human' THEN COALESCE(last_error_code,'cleanup_requires_review') ELSE last_error_code END WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO rr;
   END IF;
   UPDATE zasp_sa_multistep_prior.cleanups SET version=version+1,state=CASE WHEN op='complete' THEN 'cleaned' ELSE 'leased' END,lease_owner=CASE WHEN op<>'complete' THEN worker END,lease_token=CASE WHEN op<>'complete' THEN token END,lease_expires_at=CASE WHEN op<>'complete' THEN deadline END,completed_at=CASE WHEN op='complete' THEN (receipt_body->>'completed_at')::timestamptz END WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) RETURNING * INTO c;
  END IF;
  UPDATE public.zasp_security_agent_effects SET state=CASE WHEN op='complete' THEN 'cleaned' WHEN op='reconcile' THEN 'cleanup_failed' ELSE 'leased' END,lease_owner=CASE WHEN op NOT IN('complete','reconcile') THEN worker END,lease_token=CASE WHEN op NOT IN('complete','reconcile') THEN token END,lease_expires_at=CASE WHEN op NOT IN('complete','reconcile') THEN deadline END,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_temporary_policy') RETURNING * INTO fx;
  response:=jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'operation',op,'cleanup_id',c.cleanup_id,'reservation_id',c.reservation_id,'control_id',c.control_id,'state',c.state,'version',c.version,'attempt',c.attempt,'run_version',rr.version,'run_state',rr.state,'effect_version',fx.version,'effect_state',fx.state,'lease_expires_at',COALESCE(to_char(c.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''),'reason',c.reason,'targets',zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,s),'receipt_kind',CASE WHEN op='complete' THEN 'temporary_policy_cleaned.v1' ELSE '' END,'receipt',COALESCE(receipt_body,'{}'::jsonb),'receipt_digest',COALESCE('sha256:'||encode(receipt_digest,'hex'),''));
  IF op='complete' AND snapshot_value->>'kind'='partial' THEN response:=jsonb_set(response,'{receipt_kind}','"temporary_policy_partial_cleaned.v1"');END IF;
  IF NOT zasp_sa_multistep_prior.cleanup_wire(response,'response') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup response budget exceeded';END IF;
  INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_id,audit_id,r,s,worker,'ordered_cleanup_'||op,request_hash,jsonb_build_object('request',q-'lease_token','owner',to_jsonb(c)-'lease_token','recovery_evidence',recovery_evidence,'response',response));
 END IF;
 IF NOT zasp_sa_multistep_prior.cleanup_wire(response,'response') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup replay budget exceeded';END IF;
 IF op IN('heartbeat','store') THEN PERFORM zasp_sa_multistep_prior.cleanup_current(o,w,e,r,s);END IF;
 IF op='heartbeat' AND (original_deadline IS NULL OR original_deadline<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup heartbeat original lease expired after wait';END IF;
 IF op='complete' AND (receipt_body->'targets' IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_acknowledgements(o,w,e,r,s) OR response->>'run_state'='remediated' AND NOT zasp_sa_multistep_prior.cleanup_remediation_ready(o,w,e,r,snapshot_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup completion authority changed after wait';END IF;
 IF snapshot_value IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_snapshot(o,w,e,r,s) OR op NOT IN('complete','reconcile') AND (COALESCE(deadline,c.lease_expires_at)>='infinity'::timestamptz OR COALESCE(deadline,c.lease_expires_at)<=clock_timestamp()) OR op='complete' AND deadline<=clock_timestamp() OR NOT COALESCE(public.zasp_security_agent_action_principal_ready(),false) OR NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup authority changed after wait';END IF;
 IF op='complete' AND old_audit.audit_id IS NULL AND (marker_deadline IS NULL OR marker_deadline<=clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup execution marker expired after wait';END IF;
 RETURN response;
END $cleanup$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='zasp_sa_multistep_prior'::regnamespace AND proname LIKE 'cleanup%' LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_policy_deployment_worker',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.cleanup(text,text,jsonb) TO zasp_security_agent_action_worker;
