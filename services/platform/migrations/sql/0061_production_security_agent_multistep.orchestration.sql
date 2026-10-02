-- Caller holds transition_lock and has checked persisted authority. This
-- classification never changes a lease, erases an outcome or acknowledges a
-- deployment. Only the reviewed conservative transition consumes true.
CREATE FUNCTION zasp_sa_multistep_prior.orchestration_stop_required(o text,w text,e text,r text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $stop$
DECLARE s public.zasp_security_agent_steps%ROWTYPE;t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;
 d public.zasp_policy_deployment_work%ROWTYPE;c public.zasp_security_agent_audit%ROWTYPE;fx public.zasp_security_agent_effects%ROWTYPE;
 message_value text;request_hash bytea;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('waiting_approval','running','verifying') AND completed_at IS NULL) THEN RETURN false;END IF;
 SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0);
 BEGIN
  PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,true);
  IF s.state IN('authorized','executing') THEN PERFORM zasp_sa_multistep_prior.application_current(o,w,e,r,s.step_id);END IF;
 EXCEPTION WHEN SQLSTATE '40001' OR SQLSTATE '42501' OR SQLSTATE '55000' THEN
  GET STACKED DIAGNOSTICS message_value=MESSAGE_TEXT;
  -- Do not convert readiness, persisted hash corruption, lock contention or
  -- arbitrary database errors into terminal evidence.
  IF SQLSTATE='42501' AND message_value IN('ordered requester unavailable','ordered requester permissions rejected','ordered application approver unavailable')
   OR SQLSTATE='40001' AND message_value IN('ordered definition unavailable','ordered evidence unavailable','ordered evidence changed','ordered test changed','ordered target authority expired','ordered current authorization unavailable','ordered application approval unavailable','ordered application target changed')
   OR SQLSTATE='55000' AND message_value='ordered execution disabled' THEN RETURN true;END IF;
  RAISE;
 END;
 SELECT * INTO fx FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s.step_id,'create_temporary_policy');
 FOR t IN SELECT * FROM public.zasp_security_agent_temporary_policy_targets WHERE (organization_id,workspace_id,environment_id,run_id,step_id,phase)=(o,w,e,r,s.step_id,'apply') ORDER BY device_id LOOP
  SELECT * INTO d FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id);
  -- Forward safety-writer changes revoke the old application authority. A
  -- backwards/missing work generation remains an integrity refusal downstream.
  IF NOT EXISTS(SELECT 1 FROM public.zasp_gateway_devices WHERE (organization_id,workspace_id,environment_id,id,state)=(o,w,e,t.device_id,'active'))
   OR t.credential_id IS DISTINCT FROM (SELECT id FROM public.zasp_gateway_credentials WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id) AND revoked_at IS NULL AND expires_at>clock_timestamp() ORDER BY issued_at DESC,id DESC LIMIT 1)
   OR t.state<>'planned' AND t.expires_at<=clock_timestamp()
   OR t.state='stored' AND d.desired_generation>t.desired_generation THEN RETURN true;END IF;
  IF t.state='stored' AND d.state='leased' AND d.lease_expires_at<=clock_timestamp() THEN
   SELECT * INTO c FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s.step_id,'ordered_delivery_claim')
    AND ((body->'work')-ARRAY['desired_generation','available_at','updated_at'])=(to_jsonb(d)-ARRAY['lease_token','desired_generation','available_at','updated_at']) FOR SHARE;
   request_hash:=digest(convert_to((c.body->'request'||jsonb_build_object('lease_token',d.lease_token,'action_lease_token',fx.lease_token))::text,'UTF8'),'sha256');
   IF c.audit_id IS NULL OR c.event_digest IS DISTINCT FROM request_hash
    OR c.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_ordered_delivery',r||chr(31)||s.step_id||chr(31)||encode(request_hash,'hex'))
    OR c.body->'request'->>'source_digest' IS DISTINCT FROM 'sha256:'||encode(t.envelope_digest,'hex') OR c.body->'request'->'source_sequence' IS DISTINCT FROM to_jsonb(t.sequence)
    OR c.body->'request'->'desired_generation' IS DISTINCT FROM to_jsonb(t.desired_generation) OR c.body->'request'->>'credential_id' IS DISTINCT FROM t.credential_id
    OR c.body->'response'->'result'->'sequence' IS DISTINCT FROM to_jsonb(d.leased_sequence) OR c.body->'response'->'result'->>'input_digest' IS DISTINCT FROM 'sha256:'||encode(d.leased_input_digest,'hex')
    OR d.leased_generation IS DISTINCT FROM t.desired_generation OR d.leased_credential_id IS DISTINCT FROM t.credential_id
    OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,run_id,step_id,event_kind)=(o,w,e,r,s.step_id,'ordered_delivery_finish') AND body->'request'->>'device_id'=t.device_id AND body->'request'->'sequence'=to_jsonb(d.leased_sequence)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered expired delivery authority changed';END IF;
   RETURN true;
  END IF;
 END LOOP;
 RETURN false;
END $stop$;
ALTER FUNCTION zasp_sa_multistep_prior.orchestration_stop_required(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.orchestration_stop_required(text,text,text,text) FROM PUBLIC,zasp_security_agent_worker,zasp_security_agent_api,zasp_security_agent_action_worker,zasp_policy_deployment_worker,zasp_red_team_worker,zasp_red_team_adapter;

-- Dormant scoped reader; it grants no claim, decision, or lease-secret access.
CREATE FUNCTION zasp_sa_multistep_prior.orchestration_ready(checksum_value text,fingerprint_value text,lane text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RETURN false;END IF;
 RETURN COALESCE(CASE lane WHEN 'worker' THEN public.zasp_security_agent_principal_ready('zasp_security_agent_worker') WHEN 'action' THEN public.zasp_security_agent_action_principal_ready() WHEN 'deployment' THEN public.zasp_policy_deployment_principal_ready() WHEN 'test' THEN public.zasp_red_team_principal_ready('zasp_red_team_worker') ELSE false END,false);
END $ready$;
ALTER FUNCTION zasp_sa_multistep_prior.orchestration_ready(text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.orchestration_ready(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.orchestration_ready(text,text,text) TO zasp_security_agent_worker,zasp_security_agent_action_worker,zasp_policy_deployment_worker,zasp_red_team_worker;

-- Return at most one retained delivery claim, so the reader never multiplies
-- the reviewed 8 MiB composition bound by the number of gateway targets.
CREATE FUNCTION zasp_sa_multistep_prior.orchestration_application(o text,w text,e text,r text,q jsonb,phase_value text DEFAULT 'apply') RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $application$
DECLARE s text;ttl integer;t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;d public.zasp_policy_deployment_work%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;c public.zasp_security_agent_audit%ROWTYPE;delivery jsonb:='{}';phase text;owned_value boolean;prefix_value text;
BEGIN
 IF phase_value NOT IN('apply','cleanup') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered state phase rejected';END IF;
 prefix_value:=CASE phase_value WHEN 'apply' THEN 'ordered_delivery_' ELSE 'ordered_cleanup_delivery_' END;
 s:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 SELECT (plan->'steps'->0->>'ttl_seconds')::integer INTO ttl FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF phase_value='cleanup' OR NOT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN
 FOR t IN SELECT src.* FROM public.zasp_security_agent_temporary_policy_targets src WHERE (src.organization_id,src.workspace_id,src.environment_id,src.run_id,src.step_id,src.phase)=(o,w,e,r,s,phase_value) AND src.state='stored' ORDER BY src.device_id LOOP
  SELECT * INTO d FROM public.zasp_policy_deployment_work WHERE (organization_id,workspace_id,environment_id,device_id)=(o,w,e,t.device_id);
  SELECT * INTO a FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id)=(o,w,e,r,s) AND x.event_kind IN(prefix_value||'claim',prefix_value||'store',prefix_value||'read',prefix_value||'finish') AND x.body->'request'->>'device_id'=t.device_id AND x.body->'request'->>'credential_id'=t.credential_id AND x.body->'request'->'source_sequence'=to_jsonb(t.sequence) AND x.body->'request'->>'source_digest'='sha256:'||encode(t.envelope_digest,'hex') AND x.body->'request'->'desired_generation'=to_jsonb(t.desired_generation) ORDER BY x.created_at DESC,x.audit_id DESC LIMIT 1;
  phase:=CASE a.event_kind WHEN prefix_value||'claim' THEN 'claimed' WHEN prefix_value||'store' THEN 'stored' WHEN prefix_value||'read' THEN 'read' WHEN prefix_value||'finish' THEN 'finished' ELSE 'unclaimed' END;
  IF phase='finished' THEN CONTINUE;END IF;
  owned_value:=COALESCE(d.state='leased' AND d.lease_owner=q->>'deployment_worker_id' AND d.lease_token=q->>'deployment_lease_token' AND d.lease_expires_at>clock_timestamp(),false);
  SELECT * INTO c FROM public.zasp_security_agent_audit x WHERE (x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.event_kind)=(o,w,e,r,s,prefix_value||'claim') AND x.body->'request'->>'device_id'=t.device_id AND x.body->'request'->'desired_generation'=to_jsonb(t.desired_generation) AND x.body->'request'->>'source_digest'='sha256:'||encode(t.envelope_digest,'hex') AND x.body->'response'->'result'->'sequence'=to_jsonb(d.leased_sequence) ORDER BY x.created_at DESC,x.audit_id DESC LIMIT 1;
  delivery:=jsonb_build_object('device_id',t.device_id,'phase',phase,'owned',owned_value,'lease_expires_at',COALESCE(to_char(d.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''),'claim',CASE WHEN owned_value THEN COALESCE(c.body->'response'->'result','{}'::jsonb) ELSE '{}'::jsonb END,'digest',CASE WHEN phase IN('stored','read') THEN COALESCE((SELECT 'sha256:'||encode(b.envelope_digest,'hex') FROM public.zasp_runtime_gateway_policy_bundles b WHERE (b.organization_id,b.workspace_id,b.environment_id,b.device_id,b.sequence)=(o,w,e,t.device_id,d.leased_sequence)),'') ELSE '' END);
  EXIT;
 END LOOP;
 END IF;
 RETURN jsonb_build_object('ttl_seconds',CASE phase_value WHEN 'apply' THEN ttl ELSE 300 END,'targets',CASE phase_value WHEN 'apply' THEN COALESCE(zasp_sa_multistep_prior.application_targets(o,w,e,r,s),'[]'::jsonb) ELSE zasp_sa_multistep_prior.cleanup_targets(o,w,e,r,s) END,'delivery',delivery);
END $application$;
ALTER FUNCTION zasp_sa_multistep_prior.orchestration_application(text,text,text,text,jsonb,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.orchestration_application(text,text,text,text,jsonb,text) FROM PUBLIC,zasp_security_agent_worker,zasp_security_agent_api,zasp_security_agent_action_worker,zasp_policy_deployment_worker,zasp_red_team_worker,zasp_red_team_adapter;

CREATE FUNCTION zasp_sa_multistep_prior.orchestration_cleanup(o text,w text,e text,r text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $cleanup$
DECLARE c zasp_sa_multistep_prior.cleanups%ROWTYPE;p zasp_sa_multistep_prior.cleanup_receipts%ROWTYPE;
BEGIN
 SELECT * INTO c FROM zasp_sa_multistep_prior.cleanups WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF NOT FOUND THEN RETURN '{}'::jsonb;END IF;
 PERFORM zasp_sa_multistep_prior.cleanup_lock(o,w,e,r);
 IF c.snapshot IS DISTINCT FROM zasp_sa_multistep_prior.cleanup_snapshot(o,w,e,r,c.step_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup read authority changed';END IF;
 SELECT * INTO p FROM zasp_sa_multistep_prior.cleanup_receipts WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,c.step_id);
 IF c.state='cleaned' AND (p.run_id IS NULL OR p.digest IS DISTINCT FROM digest(convert_to(zasp_sa_multistep_prior.deployment_json(p.body),'UTF8'),'sha256') OR p.receipt_kind IS DISTINCT FROM CASE WHEN c.snapshot->>'kind'='partial' THEN 'temporary_policy_partial_cleaned.v1' ELSE 'temporary_policy_cleaned.v1' END) OR c.state<>'cleaned' AND p.run_id IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered cleanup receipt unavailable';END IF;
 RETURN jsonb_build_object('state',c.state,'version',c.version,'owned',COALESCE(c.state='leased' AND c.lease_owner=q->>'worker_id' AND c.lease_token=q->>'lease_token' AND c.lease_expires_at>clock_timestamp(),false),'lease_expires_at',COALESCE(to_char(c.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''),'application',zasp_sa_multistep_prior.orchestration_application(o,w,e,r,q,'cleanup'),'receipt_kind',COALESCE(p.receipt_kind,''),'receipt',COALESCE(p.body,'{}'::jsonb),'receipt_digest',COALESCE('sha256:'||encode(p.digest,'hex'),''));
END $cleanup$;
ALTER FUNCTION zasp_sa_multistep_prior.orchestration_cleanup(text,text,text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.orchestration_cleanup(text,text,text,text,jsonb) FROM PUBLIC,zasp_security_agent_worker,zasp_security_agent_api,zasp_security_agent_action_worker,zasp_policy_deployment_worker,zasp_red_team_worker,zasp_red_team_adapter;

CREATE FUNCTION zasp_sa_multistep_prior.orchestration_state(checksum_value text,fingerprint_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $state$
DECLARE o text;w text;e text;r text;k text;result_value jsonb;admitted_value boolean;planning_value jsonb;stop_value boolean:=false;
 parent_row public.zasp_security_agent_runs%ROWTYPE;job zasp_sa_multistep_prior.planning_jobs%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered state requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered state release unavailable';END IF;
 IF NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered state principal rejected';END IF;
 IF octet_length(q::text)>4096 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','worker_id','lease_token','deployment_worker_id','deployment_lease_token']) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered state request rejected';END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered state scope rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['worker_id','deployment_worker_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR q->>k!~'^[A-Za-z0-9_.-]{1,128}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered state worker rejected';END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['lease_token','deployment_lease_token'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR q->>k!~'^[A-Za-z0-9_.-]{16,128}$' THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered state token rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 -- The planning claim uses this same Organization -> budget -> run order.
 -- A fresh queued run has no budget/admission yet; do not invent either.
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO parent_row FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered state run unavailable';END IF;
 SELECT EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) INTO admitted_value;
 IF admitted_value THEN
  PERFORM zasp_sa_multistep_prior.transition_lock(o,w,e,r);
  PERFORM zasp_sa_multistep_prior.transition_current(o,w,e,r,false);
  PERFORM 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test') ORDER BY organization_id,workspace_id,environment_id,action_key FOR SHARE NOWAIT;
  SELECT parent_row.state IN('waiting_approval','running','verifying') AND parent_row.completed_at IS NULL AND (
   (SELECT count(*)<>4 OR NOT COALESCE(bool_and(execution_enabled),false) FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') OR (organization_id,workspace_id,environment_id)=(o,w,e) AND action_key IN('*','create_temporary_policy','run_test'))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_run_budgets WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND (stop_reason IS NOT NULL OR deadline_at IS NULL OR deadline_at<=clock_timestamp()))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND expires_at<=clock_timestamp())
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_index)=(o,w,e,r,0) AND state IN('failed','inconclusive','cancelled'))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state IN('known_failure','unknown_outcome','cleanup_failed','cleaned'))) INTO stop_value;
  IF NOT stop_value THEN stop_value:=zasp_sa_multistep_prior.orchestration_stop_required(o,w,e,r);END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts tr WHERE (tr.organization_id,tr.workspace_id,tr.environment_id,tr.run_id,tr.definition_id,tr.trigger_id)=(o,w,e,r,parent_row.definition_id,parent_row.trigger_id) AND r=public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',parent_row.definition_id||chr(31)||parent_row.trigger_id||chr(31)||tr.trigger_version::text))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
   OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered planning state changed';END IF;
 END IF;
 SELECT * INTO job FROM zasp_sa_multistep_prior.planning_jobs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF FOUND THEN
  IF NOT admitted_value AND parent_row.state NOT IN('planning','needs_human') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered planning parent changed';END IF;
  planning_value:=jsonb_build_object('state',job.state,'owned',job.worker_id=q->>'worker_id' AND job.lease_token_digest=digest(convert_to(q->>'lease_token','UTF8'),'sha256') AND job.lease_expires_at>clock_timestamp(),'lease_expires_at',to_char(job.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 ELSIF NOT admitted_value AND (parent_row.state<>'queued' OR parent_row.version<>1 OR parent_row.attempt<>0 OR parent_row.plan_hash IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered queued state changed';END IF;
 SELECT jsonb_build_object('contract_version',61,'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'run_state',rr.state,'run_version',rr.version,
  'steps',(SELECT jsonb_agg(jsonb_build_object('step_id',s.step_id,'step_index',s.step_index,'state',s.state,'step_version',s.version,'approval_state',COALESCE(a.state,''),'approval_version',COALESCE(a.version,0),'effect_state',COALESCE(f.state,''),'effect_version',COALESCE(f.version,0),'attempt',COALESCE(f.attempt,0),'lease_expires_at',COALESCE(to_char(f.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''),'owned',COALESCE(f.lease_owner=q->>'worker_id' AND f.lease_token=q->>'lease_token' AND f.lease_expires_at>clock_timestamp(),false)) ORDER BY s.step_index)
   FROM public.zasp_security_agent_steps s LEFT JOIN public.zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id,step_id) LEFT JOIN public.zasp_security_agent_effects f USING(organization_id,workspace_id,environment_id,run_id,step_id)
   WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(o,w,e,r))) INTO result_value FROM public.zasp_security_agent_runs rr WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id)=(o,w,e,r);
 result_value:=result_value||jsonb_build_object('steps',CASE WHEN admitted_value THEN result_value->'steps' ELSE '[]'::jsonb END,'admitted',admitted_value,'planning',COALESCE(planning_value,'{}'::jsonb));
 result_value:=result_value||jsonb_build_object('application',CASE WHEN admitted_value THEN zasp_sa_multistep_prior.orchestration_application(o,w,e,r,q) ELSE '{}'::jsonb END,'stop_required',stop_value,
  'test',COALESCE((SELECT jsonb_build_object('test_run_id',l.test_run_id,'test_definition_id',l.test_definition_id,'test_definition_version',l.test_definition_version,'target_id',l.target_id,'target_kind',l.target_kind,'categories',l.test_categories,'input_digest',encode(c.input_digest,'hex'),'child_state',c.state,'attempt',c.attempt,'owned',COALESCE(c.worker_id=q->>'worker_id' AND c.lease_token=convert_to(q->>'lease_token','UTF8') AND c.lease_expires_at>clock_timestamp(),false),'lease_expires_at',COALESCE(to_char(c.lease_expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),''),'input_manifest',COALESCE(p.manifest,'{}'::jsonb),'input_body',COALESCE(convert_from(p.body,'UTF8'),''),
    'observations',COALESCE((SELECT jsonb_agg(jsonb_build_object('category',j.category,'state',j.state,'observation',CASE WHEN j.state='completed' THEN jsonb_build_object('target_comparison',j.target_resolution->'comparison','schema_version','red-team-linked-observation-v1','run_id',l.test_run_id,'category',j.category,'credential_version_digest',encode(j.credential_version_digest,'hex'),'observation',jsonb_build_object('http_status',j.http_status,'response_digest',encode(j.response_digest,'hex'),'protected',j.protected)) ELSE '{}'::jsonb END) ORDER BY j.category) FROM public.zasp_security_agent_test_invocations j WHERE (j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(o,w,e,l.test_run_id)),'[]'::jsonb))
   FROM public.zasp_security_agent_test_links l JOIN public.zasp_red_team_runs c ON (c.organization_id,c.workspace_id,c.environment_id,c.run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.test_run_id) LEFT JOIN zasp_sa_multistep_prior.test_inputs p ON (p.organization_id,p.workspace_id,p.environment_id,p.run_id,p.step_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id)
   WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id)=(o,w,e,r)),'{}'::jsonb),'cleanup',CASE WHEN admitted_value THEN zasp_sa_multistep_prior.orchestration_cleanup(o,w,e,r,q) ELSE '{}'::jsonb END);
 IF result_value IS NULL OR jsonb_array_length(result_value->'steps') IS DISTINCT FROM (CASE WHEN admitted_value THEN 2 ELSE 0 END) OR octet_length(result_value::text)>9437184 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered state unavailable';END IF;
 IF NOT COALESCE(public.zasp_sa_multistep_readiness(checksum_value,fingerprint_value),false) OR NOT COALESCE(public.zasp_security_agent_principal_ready('zasp_security_agent_worker'),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered state authority changed';END IF;
 RETURN result_value;
END $state$;
ALTER FUNCTION zasp_sa_multistep_prior.orchestration_state(text,text,jsonb) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.orchestration_state(text,text,jsonb) FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_action_worker,zasp_policy_deployment_worker,zasp_red_team_worker,zasp_red_team_adapter;
GRANT EXECUTE ON FUNCTION zasp_sa_multistep_prior.orchestration_state(text,text,jsonb) TO zasp_security_agent_worker;
