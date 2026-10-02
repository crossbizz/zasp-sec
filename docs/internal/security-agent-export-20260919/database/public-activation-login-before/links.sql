CREATE FUNCTION public.zasp_sa_export_principal_ready(expected_role text) RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $caller$
 SELECT COALESCE(public.zasp_security_agent_principal_ready(expected_role),false)
 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE starts_with(r.rolname,'zasp_') AND r.rolname<>expected_role AND pg_has_role(session_user,r.oid,'MEMBER'))
$caller$;

CREATE FUNCTION public.zasp_sa_export_principal(o text,w text,e text,actor text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $principal$
BEGIN
 IF NOT COALESCE(public.zasp_valid_product_id(actor),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export actor rejected';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE (organization_id,principal_id,active)=(o,actor,true) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export membership rejected';END IF;
 -- Match browser authority: lock membership, then read fresh effective scopes.
 -- A current group mapping is valid without a redundant direct scope row.
 IF NOT EXISTS(SELECT 1 FROM public.zasp_identity_admin_effective_scopes(actor,o) a WHERE (a.organization_id,a.workspace_id,a.environment_id)=(o,w,e) AND a.permissions ?& ARRAY['view','manage_workflows']) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export source permission rejected';END IF;
END $principal$;

CREATE FUNCTION public.zasp_sa_export_authorize(o text,w text,e text,r text,s text,phase text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authorize$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;d public.zasp_security_agent_definition_versions%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;approval public.zasp_security_agent_approvals%ROWTYPE;item jsonb;trigger_kind_value text;
BEGIN
 IF phase IS NULL OR phase NOT IN('admit','capture','prepare','publish','retrieve') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export phase unavailable';END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) AND state<>'simulated';
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export run rejected';END IF;
 SELECT * INTO st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,s,'create_evidence_export');
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export step rejected';END IF;
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,definition_version)=(o,w,e,r,rr.definition_id,rr.definition_version) FOR SHARE;
 IF NOT FOUND OR p.plan_hash IS DISTINCT FROM rr.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR p.plan->'verification'->>'kind' IS DISTINCT FROM 'export' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export plan changed';END IF;
 IF p.plan IS DISTINCT FROM jsonb_build_object('definition_id',rr.definition_id,'definition_version',rr.definition_version,'catalog_version',p.catalog_version,'evidence_ids',jsonb_build_array(rr.trigger_id),'steps',p.plan->'steps','verification',jsonb_build_object('kind','export'),'expires_at',to_char(p.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
 OR jsonb_typeof(p.plan->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(p.plan->'steps')<>1 OR st.step_index<>0
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_trigger_receipts t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id,t.trigger_digest)=(o,w,e,r,rr.definition_id,rr.trigger_id,p.trigger_digest)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export plan authority binding changed';END IF;
 item:=p.plan->'steps'->st.step_index;
 PERFORM public.zasp_sa_export_selection(item->'evidence_ids');
 IF item IS DISTINCT FROM jsonb_build_object('index',st.step_index,'step_id',s,'action','create_evidence_export','target_id',r,'evidence_ids',item->'evidence_ids','authorization',st.authorization_result) OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export input changed';END IF;
 SELECT * INTO d FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) FOR SHARE;
 IF NOT FOUND OR d.definition_digest IS DISTINCT FROM digest(convert_to(d.definition::text,'UTF8'),'sha256') OR NOT COALESCE(public.zasp_valid_product_id(d.actor_id),false) OR NOT d.definition->'allowed_actions' ? 'create_evidence_export' OR d.definition->>'verification_kind' IS DISTINCT FROM 'export' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export definition changed';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF FOUND THEN
  IF (l.plan_hash,l.input_digest,l.definition_id,l.definition_version,l.definition_digest,l.authority_principal_id,l.requester_id,l.selection) IS DISTINCT FROM (p.plan_hash,st.input_digest,d.definition_id,d.version,d.definition_digest,d.actor_id,CASE WHEN public.zasp_valid_product_id(rr.requested_by) THEN rr.requested_by ELSE NULL END,item->'evidence_ids') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export replay input changed';END IF;
 ELSIF phase='retrieve' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export link unavailable';END IF;
 IF phase='retrieve' THEN RETURN;END IF;
 IF phase='admit' AND (rr.state<>'planning' OR st.state<>'authorized' OR p.expires_at<=clock_timestamp()) OR phase<>'admit' AND (rr.state NOT IN('running','verifying') OR st.state<>'executing') OR d.activation NOT IN('autonomous','supervised') OR st.authorization_result IS DISTINCT FROM (CASE d.activation WHEN 'autonomous' THEN 'autonomous' ELSE 'approval_required' END) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export execution unavailable';END IF;
 IF d.activation='supervised' THEN
  SELECT * INTO approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s) FOR SHARE;
  IF NOT FOUND OR approval.state<>'approved' OR approval.plan_hash IS DISTINCT FROM p.plan_hash OR approval.requester_id IS DISTINCT FROM rr.requested_by OR approval.approver_id IS NULL OR approval.approver_id=approval.requester_id OR approval.fresh_auth_at IS NULL OR approval.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export approval unavailable';END IF;
 END IF;
 PERFORM 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version,activation)=(o,w,e,d.definition_id,d.version,d.activation) AND deleted_at IS NULL AND body=d.definition AND body->'enabled'='true'::jsonb FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export definition no longer active';END IF;
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,'create_evidence_export');
 PERFORM public.zasp_sa_export_principal(o,w,e,d.actor_id);
 PERFORM public.zasp_sa_export_source_permissions(o,w,e,d.actor_id,item->'evidence_ids');
 SELECT t.trigger_kind INTO STRICT trigger_kind_value FROM public.zasp_security_agent_trigger_receipts t WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id,t.trigger_digest)=(o,w,e,r,rr.definition_id,rr.trigger_id,p.trigger_digest);
 IF trigger_kind_value='manual' THEN
  -- Manual intent always needs its own current product principal. A worker-
  -- shaped requested_by cannot borrow the scheduled definition actor's rights.
  PERFORM public.zasp_sa_export_principal(o,w,e,rr.requested_by);PERFORM public.zasp_sa_export_source_permissions(o,w,e,rr.requested_by,item->'evidence_ids');
 ELSIF trigger_kind_value IN('finding','attack_path','runtime_decision') THEN
  -- Explicit scheduled receipts rely on the exact version-bound actor checked
  -- above and the registered caller, never on a worker label as a principal.
  IF public.zasp_valid_product_id(rr.requested_by) THEN PERFORM public.zasp_sa_export_principal(o,w,e,rr.requested_by);PERFORM public.zasp_sa_export_source_permissions(o,w,e,rr.requested_by,item->'evidence_ids');END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export trigger authority rejected';END IF;
END $authorize$;

CREATE FUNCTION public.zasp_sa_export_source_permissions(o text,w text,e text,actor text,selection jsonb) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $permissions$
DECLARE permissions jsonb;
BEGIN
 SELECT a.permissions INTO permissions FROM public.zasp_identity_admin_effective_scopes(actor,o) a WHERE (a.organization_id,a.workspace_id,a.environment_id)=(o,w,e);
 IF permissions IS NULL OR NOT permissions ? 'view'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(selection) x WHERE x->>'source_kind'='runtime_decision') AND NOT permissions ? 'investigate_sessions'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(selection) x WHERE x->>'source_kind'='run_audit') AND NOT permissions ? 'view_audit' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export selected source permission rejected';END IF;
END $permissions$;

CREATE FUNCTION public.zasp_sa_export_execute_run(o text,w text,e text,r text,worker_value text,lease_value text,audit_value text,correlation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $execute$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;d public.zasp_security_agent_definition_versions%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;p public.zasp_compliance_export_policy%ROWTYPE;selection jsonb;request_value jsonb;result_value jsonb;id_value text;deadline timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export authority unavailable';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[o,w,e,r,audit_value,correlation_value]) id WHERE NOT COALESCE(public.zasp_valid_product_id(id),false)) OR NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export dispatch identity rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export parent unavailable';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF FOUND THEN
  IF (l.dispatch_worker,l.dispatch_token_digest) IS DISTINCT FROM (worker_value,digest(lease_value,'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export dispatch replay identity changed';END IF;
  PERFORM public.zasp_sa_export_authorize(o,w,e,r,l.step_id,'retrieve');RETURN l.dispatch_result||jsonb_build_object('replayed',true);
 END IF;
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export budget stopped';END IF;
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,action_key)=(o,w,e,r,'create_evidence_export') FOR UPDATE;
 PERFORM public.zasp_sa_export_authorize(o,w,e,r,st.step_id,'admit');
 SELECT definition.* INTO STRICT d FROM public.zasp_security_agent_definition_versions definition WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version);
 SELECT plan->'steps'->st.step_index->'evidence_ids' INTO STRICT selection FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 PERFORM public.zasp_sa_export_collect(o,w,e,r,st.step_id,selection,clock_timestamp());
 SELECT * INTO STRICT p FROM public.zasp_compliance_export_policy WHERE revision='compliance-limits-v1' FOR UPDATE;
 PERFORM public.zasp_sa_export_authorize(o,w,e,r,st.step_id,'admit');
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export lease changed';END IF;
 IF (SELECT count(*)>=p.scope_active FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id)=(o,w,e) AND state='pending') OR (SELECT count(*)>=p.deployment_active FROM public.zasp_compliance_export_jobs WHERE state='pending')
 OR (SELECT count(*)>=p.scope_jobs OR COALESCE(sum(retained_bytes),0)+12582912>p.scope_bytes FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id)=(o,w,e))
 OR (SELECT count(*)>=p.deployment_jobs OR COALESCE(sum(retained_bytes),0)+12582912>p.deployment_bytes FROM public.zasp_compliance_export_jobs) THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='export capacity exhausted';END IF;
 IF NOT public.zasp_security_agent_budget_reserve_step(o,w,e,r,worker_value,lease_value,st.step_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export step budget stopped';END IF;
 deadline:=rr.lease_expires_at;id_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_export',r||chr(31)||st.step_id);
 request_value:=jsonb_build_object('run_id',r,'step_id',st.step_id,'selection',selection);
 result_value:=jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',st.step_id,'export_id',id_value,'state','pending','run_version',rr.version+1,'replayed',false);
 INSERT INTO public.zasp_compliance_export_scopes(organization_id,workspace_id,environment_id) VALUES(o,w,e) ON CONFLICT DO NOTHING;
 INSERT INTO public.zasp_security_agent_effects(organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,state,outcome_id,result_digest) VALUES(o,w,e,r,st.step_id,'create_evidence_export',st.input_digest,'pending',id_value,digest(convert_to(result_value::text,'UTF8'),'sha256'));
 INSERT INTO public.zasp_compliance_export_jobs(organization_id,workspace_id,environment_id,export_id,principal_id,session_digest,idempotency_key,request,request_digest,policy_revision,mapping_revision,job_origin,agent_run_id,agent_step_id) VALUES(o,w,e,id_value,d.actor_id,NULL,'agent-step:'||st.step_id,request_value,digest(convert_to(request_value::text,'UTF8'),'sha256'),p.revision,'security-agent-run-evidence-v1','agent_run',r,st.step_id);
 INSERT INTO public.zasp_sa_export_links(organization_id,workspace_id,environment_id,run_id,step_id,export_id,plan_hash,input_digest,definition_id,definition_version,definition_digest,authority_principal_id,requester_id,selection,dispatch_result,dispatch_worker,dispatch_token_digest) VALUES(o,w,e,r,st.step_id,id_value,rr.plan_hash,st.input_digest,d.definition_id,d.version,d.definition_digest,d.actor_id,CASE WHEN public.zasp_valid_product_id(rr.requested_by) THEN rr.requested_by ELSE NULL END,selection,result_value,worker_value,digest(lease_value,'sha256'));
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,r,st.step_id,worker_value,'effect_dispatched',digest(convert_to(result_value::text,'UTF8'),'sha256'),jsonb_build_object('run_id',r,'step_id',st.step_id,'action','create_evidence_export','export_id',id_value));
 PERFORM public.zasp_sa_export_authorize(o,w,e,r,st.step_id,'admit');
 IF NOT public.zasp_security_agent_budget_can_start(o,w,e,r,worker_value,lease_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export post-write budget stopped';END IF;
 UPDATE public.zasp_security_agent_steps SET state='executing',version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,st.step_id);
 UPDATE public.zasp_security_agent_runs SET state='verifying',lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export dispatch lease expired';END IF;
 RETURN result_value;
END $execute$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_export_execute_run(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_sa_export_job_authorize(j public.zasp_compliance_export_jobs,phase text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $job_authorize$
BEGIN
 IF j.job_origin='browser' THEN
  PERFORM public.zasp_compliance_authorize(j.organization_id,j.workspace_id,j.environment_id,j.principal_id,j.session_digest);
 ELSE
  IF NOT EXISTS(SELECT 1 FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.export_id,l.authority_principal_id)=(j.organization_id,j.workspace_id,j.environment_id,j.agent_run_id,j.agent_step_id,j.export_id,j.principal_id)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export job binding rejected';END IF;
  PERFORM public.zasp_sa_export_authorize(j.organization_id,j.workspace_id,j.environment_id,j.agent_run_id,j.agent_step_id,phase);
 END IF;
END $job_authorize$;

CREATE FUNCTION public.zasp_sa_export_capture_job(j public.zasp_compliance_export_jobs) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $capture_job$
DECLARE captured jsonb;stamp timestamptz;
BEGIN
 PERFORM public.zasp_sa_export_job_authorize(j,'capture');
 IF j.snapshot IS NULL THEN
  stamp:=clock_timestamp();
  -- The STABLE collector and update share one statement snapshot. Its ordered
  -- selection comes from the immutable link, independently of snapshot bytes.
  UPDATE public.zasp_compliance_export_jobs job SET snapshot=public.zasp_sa_export_collect(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.selection,stamp),snapshot_at=stamp
  FROM public.zasp_sa_export_links l WHERE (job.organization_id,job.workspace_id,job.environment_id,job.export_id)=(j.organization_id,j.workspace_id,j.environment_id,j.export_id) AND (l.organization_id,l.workspace_id,l.environment_id,l.export_id)=(job.organization_id,job.workspace_id,job.environment_id,job.export_id) RETURNING job.snapshot INTO STRICT captured;
  UPDATE public.zasp_compliance_export_jobs SET snapshot_digest=digest(convert_to(captured::text,'UTF8'),'sha256') WHERE (organization_id,workspace_id,environment_id,export_id)=(j.organization_id,j.workspace_id,j.environment_id,j.export_id);
 ELSE captured:=j.snapshot;END IF;
 PERFORM public.zasp_sa_export_job_authorize(j,'capture');
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export capture lease expired';END IF;
 RETURN jsonb_build_object('snapshot',captured,'sha256',encode(digest(convert_to(captured::text,'UTF8'),'sha256'),'hex'),'mapping_revision',j.mapping_revision);
END $capture_job$;

DO $shared_lifecycle$
DECLARE sig text;d text;anchor text;replacement text;
BEGIN
 -- Preserve exact predecessor definitions, owners and ACLs for unused rollback.
 FOREACH sig IN ARRAY ARRAY['public.zasp_compliance_export_claim(text,text,text,text,text,text,text,text,text)','public.zasp_compliance_export_locked(text,text,text,text,text,text,bigint,text,text)','public.zasp_compliance_export_capture(text,text,text,text,text,text,bigint,jsonb,text,text)','public.zasp_compliance_export_prepare_artifact(text,text,text,text,text,text,bigint,jsonb,text,text)','public.zasp_compliance_export_finish(text,text,text,text,text,text,bigint,jsonb,text,text)'] LOOP
  PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
  IF starts_with(sig,'public.zasp_compliance_export_claim(') THEN
   anchor:='''sha256'',encode(j.artifact_digest,''hex''));';
   replacement:='''sha256'',encode(j.artifact_digest,''hex''))||CASE WHEN j.job_origin=''agent_run'' THEN (SELECT jsonb_build_object(''job_origin'',''agent_run'',''binding'',jsonb_build_object(''run_id'',l.run_id,''step_id'',l.step_id,''selection'',l.selection)) FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.export_id,l.run_id,l.step_id)=(j.organization_id,j.workspace_id,j.environment_id,j.export_id,j.agent_run_id,j.agent_step_id)) ELSE ''{}''::jsonb END;';
  ELSIF starts_with(sig,'public.zasp_compliance_export_locked(') THEN
   anchor:='SELECT * INTO j FROM public.zasp_compliance_export_jobs';
   -- Cancellation and execute-phase storage admission both acquire parent,
   -- then job. The initial lookup grants nothing and cannot change binding.
   replacement:='PERFORM 1 FROM public.zasp_security_agent_runs r JOIN public.zasp_compliance_export_jobs x ON (x.organization_id,x.workspace_id,x.environment_id,x.agent_run_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id) WHERE (x.organization_id,x.workspace_id,x.environment_id,x.export_id)=(org_value,workspace_value,environment_value,id_value) AND x.job_origin=''agent_run'' FOR UPDATE OF r; SELECT * INTO j FROM public.zasp_compliance_export_jobs';
  ELSIF starts_with(sig,'public.zasp_compliance_export_capture(') THEN
   anchor:='PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);';
   replacement:='IF j.job_origin=''agent_run'' THEN RETURN public.zasp_sa_export_capture_job(j);END IF; '||anchor;
  ELSE
   anchor:='PERFORM public.zasp_compliance_authorize(org_value,workspace_value,environment_value,j.principal_id,j.session_digest);';
   replacement:='PERFORM public.zasp_sa_export_job_authorize(j,'||quote_literal(CASE WHEN starts_with(sig,'public.zasp_compliance_export_prepare_artifact(') THEN 'prepare' ELSE 'publish' END)||');';
  END IF;
  IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export lifecycle predecessor changed';END IF;d:=replace(d,anchor,replacement);
  IF starts_with(sig,'public.zasp_compliance_export_prepare_artifact(') THEN
   anchor:='parameters_value->>''renderer_revision'' !~ ''^compliance-envelope-v[1-9][0-9]{0,3}$''';
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export renderer predecessor changed';END IF;
   replacement:='parameters_value->>''renderer_revision'' IS DISTINCT FROM (CASE WHEN j.job_origin=''agent_run'' THEN ''security-agent-evidence-envelope-v1'' ELSE ''compliance-envelope-v1'' END)';
   d:=replace(d,anchor,replacement);
   d:=replace(d,'IF j.package IS NULL THEN','IF j.package IS NOT NULL AND j.renderer_revision IS DISTINCT FROM (CASE WHEN j.job_origin=''agent_run'' THEN ''security-agent-evidence-envelope-v1'' ELSE ''compliance-envelope-v1'' END) THEN RAISE EXCEPTION USING ERRCODE=''40001'',MESSAGE=''export renderer origin rejected'';END IF; IF j.package IS NULL THEN');
  END IF;
  EXECUTE d;
 END LOOP;
END $shared_lifecycle$;

CREATE FUNCTION public.zasp_sa_export_settlement_claim(worker_value text,lease_value text,lease_seconds integer,claim_limit integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $claim$
DECLARE l public.zasp_sa_export_links%ROWTYPE;result_value jsonb:='[]';rv bigint;expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export settlement authority rejected';END IF;
 IF NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128 AND lease_seconds BETWEEN 30 AND 300 AND claim_limit BETWEEN 1 AND 25,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export settlement claim rejected';END IF;
 FOR l IN
  WITH due AS (SELECT x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.settlement_last_claimed_at,x.created_at,row_number() OVER(PARTITION BY x.organization_id,x.workspace_id,x.environment_id ORDER BY x.settlement_last_claimed_at,x.created_at,x.run_id,x.step_id) ordinal
   FROM public.zasp_sa_export_links x JOIN public.zasp_security_agent_runs r USING(organization_id,workspace_id,environment_id,run_id) JOIN public.zasp_compliance_export_jobs j USING(organization_id,workspace_id,environment_id,export_id)
   WHERE x.settled_at IS NULL AND (x.settlement_lease_expires_at IS NULL OR x.settlement_lease_expires_at<=clock_timestamp()) AND (j.state IN('completed','failed') OR r.state NOT IN('queued','planning','waiting_approval','running','verifying')))
  SELECT x.* FROM due d JOIN public.zasp_sa_export_links x USING(organization_id,workspace_id,environment_id,run_id,step_id)
  ORDER BY d.ordinal,d.settlement_last_claimed_at,d.created_at,d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id LIMIT claim_limit FOR UPDATE OF x SKIP LOCKED
 LOOP
  -- The due alias can retain an older READ COMMITTED candidate after another
  -- claimant commits. Recheck the current locked tuple before replacing a lease.
  CONTINUE WHEN l.settled_at IS NOT NULL OR (l.settlement_lease_expires_at IS NOT NULL AND l.settlement_lease_expires_at>clock_timestamp());
  -- No parent lease, budget reservation, actor permission or upload authority.
  expiry:=clock_timestamp()+make_interval(secs=>lease_seconds);
  UPDATE public.zasp_sa_export_links SET settlement_worker=worker_value,settlement_token_digest=digest(lease_value,'sha256'),settlement_lease_expires_at=expiry,settlement_last_claimed_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id);
  SELECT version INTO STRICT rv FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(l.organization_id,l.workspace_id,l.environment_id,l.run_id);
  result_value:=result_value||jsonb_build_array(jsonb_build_object('organization_id',l.organization_id,'workspace_id',l.workspace_id,'environment_id',l.environment_id,'run_id',l.run_id,'step_id',l.step_id,'export_id',l.export_id,'run_version',rv,'lease_expires_at',expiry));
 END LOOP;
 RETURN result_value;
END $claim$;

CREATE FUNCTION public.zasp_sa_export_settle(o text,w text,e text,r text,worker_value text,lease_value text,audit_value text,correlation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $settle$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;j public.zasp_compliance_export_jobs%ROWTYPE;result_value jsonb;facts jsonb;reason_value text;stopped boolean;deadline timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export settlement authority rejected';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[o,w,e,r,audit_value,correlation_value]) id WHERE NOT COALESCE(public.zasp_valid_product_id(id),false)) OR NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export settlement identity rejected';END IF;
 -- Common order is parent, link, job. Claim takes only the link lock and
 -- cannot authorize storage. Cleanup never needs this parent lease.
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export settlement parent unavailable';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT FOUND OR (l.settlement_worker,l.settlement_token_digest) IS DISTINCT FROM (worker_value,digest(lease_value,'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export settlement lease rejected';END IF;
 IF l.settled_at IS NOT NULL THEN
  IF (l.settlement_audit_id,l.settlement_correlation_id) IS DISTINCT FROM (audit_value,correlation_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export settlement replay rejected';END IF;
  RETURN l.settlement_result||jsonb_build_object('replayed',true);
 END IF;
 deadline:=l.settlement_lease_expires_at;
 IF NOT COALESCE(deadline>clock_timestamp(),false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export settlement lease expired';END IF;
 PERFORM public.zasp_sa_export_authorize(o,w,e,r,l.step_id,'retrieve');
 PERFORM 1 FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key,input_digest,outcome_id)=(o,w,e,r,l.step_id,'create_evidence_export',l.input_digest,l.export_id) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export settlement effect changed';END IF;
 SELECT * INTO STRICT j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id,job_origin,agent_run_id,agent_step_id)=(o,w,e,l.export_id,'agent_run',r,l.step_id) FOR UPDATE;
 stopped:=rr.state NOT IN('queued','planning','waiting_approval','running','verifying');
 IF NOT stopped AND j.state='pending' THEN RETURN jsonb_build_object('run_id',r,'run_version',rr.version,'step_id',l.step_id,'export_id',l.export_id,'state','verifying','reason','export_pending','settled',false,'replayed',false);END IF;
 IF stopped THEN
  reason_value:=CASE WHEN rr.state='cancelled' THEN 'export_cancelled' ELSE 'export_parent_stopped' END;
  -- Intent permits an in-flight provider call. Retain bytes and the obligation
  -- to reconcile; no failed/stopped parent can publish or authorize a new PUT.
  UPDATE public.zasp_compliance_export_jobs SET state=CASE WHEN state='pending' THEN 'failed' ELSE state END,phase='terminal',failure_code=CASE WHEN state='pending' THEN reason_value ELSE failure_code END,
   storage_state=CASE WHEN package IS NOT NULL AND receipt_version IS NULL THEN 'reconcile_required' ELSE storage_state END,
   retrieval_expires_at=least(retrieval_expires_at,clock_timestamp()),lease_expires_at=NULL,lease_digest=NULL,next_attempt_at=clock_timestamp()
   WHERE (organization_id,workspace_id,environment_id,export_id)=(o,w,e,l.export_id) RETURNING * INTO j;
 ELSE
  reason_value:=CASE WHEN j.state='completed' AND j.storage_state='verified' AND j.receipt_version IS NOT NULL AND j.artifact_digest IS NOT NULL AND j.artifact_size>0 AND j.renderer_revision='security-agent-evidence-envelope-v1' AND digest(j.package,'sha256')=j.artifact_digest THEN 'export_available' ELSE 'export_failed' END;
  UPDATE public.zasp_security_agent_runs SET state='needs_human',last_error_code=reason_value,version=version+1,completed_at=clock_timestamp(),updated_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) RETURNING * INTO rr;
  UPDATE public.zasp_security_agent_steps SET state=CASE WHEN reason_value='export_available' THEN 'succeeded' ELSE 'failed' END,version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,l.step_id);
 END IF;
 facts:=jsonb_build_object('export_id',j.export_id,'state',j.state,'storage_state',j.storage_state,'sha256',encode(j.artifact_digest,'hex'),'version',j.receipt_version,'size',j.artifact_size,'retained_bytes',j.retained_bytes,'retrieval_expires_at',j.retrieval_expires_at);
 result_value:=jsonb_build_object('run_id',r,'run_version',rr.version,'step_id',l.step_id,'export_id',l.export_id,'state',rr.state,'reason',reason_value,'settled',true,'replayed',false);
 UPDATE public.zasp_security_agent_effects SET state=CASE WHEN reason_value='export_available' THEN 'succeeded' WHEN j.storage_state IN('intent','unknown','reconcile_required','delete_pending') THEN 'cleanup_pending' ELSE 'known_failure' END,result_digest=digest(convert_to(facts::text,'UTF8'),'sha256'),version=version+1,updated_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,l.step_id,'create_evidence_export');
 UPDATE public.zasp_sa_export_links SET settled_at=clock_timestamp(),settlement_result=result_value,settlement_snapshot=facts,settlement_audit_id=audit_value,settlement_correlation_id=correlation_value WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,l.step_id);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,step_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,r,l.step_id,worker_value,'export_settled',digest(convert_to(facts::text,'UTF8'),'sha256'),result_value);
 IF deadline<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export settlement lease expired';END IF;
 RETURN result_value;
END $settle$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_export_settlement_claim(text,text,integer,integer,text,text),public.zasp_sa_export_settle(text,text,text,text,text,text,text,text,text,text) TO zasp_security_agent_worker;

-- Historical action detail is intent plus a checked effect receipt. It is not
-- download authority and does not recollect mutable evidence or expose storage.
CREATE FUNCTION public.zasp_sa_export_public_step(o text,w text,e text,r text,step_value jsonb) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $public_step$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;f public.zasp_security_agent_effects%ROWTYPE;j public.zasp_compliance_export_jobs%ROWTYPE;item jsonb;receipt jsonb;facts jsonb;expected_state text;
BEGIN
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,step_value->>'step_id','create_evidence_export');
 SELECT * INTO STRICT p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,plan_hash,definition_id,definition_version)=(o,w,e,r,rr.plan_hash,rr.definition_id,rr.definition_version);
 item:=p.plan->'steps'->st.step_index;
 PERFORM public.zasp_sa_export_selection(item->'evidence_ids');
 IF p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR p.plan->'verification' IS DISTINCT FROM jsonb_build_object('kind','export')
 OR item IS DISTINCT FROM jsonb_build_object('index',st.step_index,'step_id',st.step_id,'action','create_evidence_export','target_id',r,'evidence_ids',item->'evidence_ids','authorization',st.authorization_result)
 OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')
 OR step_value->>'action' IS DISTINCT FROM st.action_key OR step_value->'index' IS DISTINCT FROM to_jsonb(st.step_index)
 OR step_value->'arguments' IS DISTINCT FROM jsonb_build_object('target_id',r,'evidence_ids',item->'evidence_ids')
 OR step_value->'control_expires_at' IS DISTINCT FROM 'null'::jsonb
 OR step_value->'apply_targets' IS DISTINCT FROM '{"total":0,"verified":0}'::jsonb OR step_value->'cleanup_targets' IS DISTINCT FROM '{"total":0,"verified":0}'::jsonb
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public plan changed';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,st.step_id);
 SELECT * INTO f FROM public.zasp_security_agent_effects WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,r,st.step_id,'create_evidence_export');
 IF l.run_id IS NULL THEN
  IF f.run_id IS NOT NULL OR step_value->'effect' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public link unavailable';END IF;
  RETURN step_value;
 END IF;
 SELECT * INTO STRICT j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id,job_origin,agent_run_id,agent_step_id)=(o,w,e,l.export_id,'agent_run',r,st.step_id);
 IF (l.plan_hash,l.input_digest,l.definition_id,l.definition_version,l.action_key,l.job_origin) IS DISTINCT FROM (p.plan_hash,st.input_digest,rr.definition_id,rr.definition_version,st.action_key,'agent_run'::text)
 OR l.selection IS DISTINCT FROM item->'evidence_ids' OR j.request IS DISTINCT FROM jsonb_build_object('run_id',r,'step_id',st.step_id,'selection',l.selection)
 OR j.request_digest IS DISTINCT FROM digest(convert_to(j.request::text,'UTF8'),'sha256')
 OR f.input_digest IS DISTINCT FROM l.input_digest OR f.outcome_id IS DISTINCT FROM l.export_id OR f.result_digest IS NULL
 OR step_value->'effect' IS DISTINCT FROM jsonb_build_object('step_id',st.step_id,'action',st.action_key,'state',f.state,'outcome_id',l.export_id,'result_digest','sha256:'||encode(f.result_digest,'hex'))
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public binding changed';END IF;
 receipt:=l.dispatch_result;
 IF receipt IS DISTINCT FROM jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',st.step_id,'export_id',l.export_id,'state','pending','run_version',receipt->'run_version','replayed',false)
 OR jsonb_typeof(receipt->'run_version') IS DISTINCT FROM 'number' OR NOT COALESCE(receipt->>'run_version' ~ '^[1-9][0-9]*$',false) OR (receipt->>'run_version')::numeric>rr.version
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public dispatch changed';END IF;
 IF l.settled_at IS NULL THEN
  IF f.state IS DISTINCT FROM 'pending' OR f.result_digest IS DISTINCT FROM digest(convert_to(receipt::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public pending changed';END IF;
 ELSE
  receipt:=l.settlement_result;facts:=l.settlement_snapshot;
  IF receipt IS DISTINCT FROM jsonb_build_object('run_id',r,'run_version',receipt->'run_version','step_id',st.step_id,'export_id',l.export_id,'state',receipt->'state','reason',receipt->'reason','settled',true,'replayed',false)
  OR jsonb_typeof(receipt->'run_version') IS DISTINCT FROM 'number' OR NOT COALESCE(receipt->>'run_version' ~ '^[1-9][0-9]*$',false) OR (receipt->>'run_version')::numeric>rr.version
  OR NOT COALESCE(receipt->>'state' IN('contained','remediated','needs_human','failed','inconclusive','cancelled'),false) OR NOT COALESCE(receipt->>'reason' IN('export_available','export_failed','export_cancelled','export_parent_stopped'),false)
  OR facts IS DISTINCT FROM jsonb_build_object('export_id',l.export_id,'state',facts->'state','storage_state',facts->'storage_state','sha256',facts->'sha256','version',facts->'version','size',facts->'size','retained_bytes',facts->'retained_bytes','retrieval_expires_at',facts->'retrieval_expires_at')
  OR f.result_digest IS DISTINCT FROM digest(convert_to(facts::text,'UTF8'),'sha256')
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public settlement changed';END IF;
  expected_state:=CASE WHEN receipt->>'reason'='export_available' THEN 'succeeded' WHEN facts->>'storage_state' IN('intent','unknown','reconcile_required','delete_pending') THEN 'cleanup_pending' ELSE 'known_failure' END;
  IF f.state IS DISTINCT FROM expected_state OR expected_state='succeeded' AND (receipt->>'state' IS DISTINCT FROM 'needs_human' OR facts->>'state' IS DISTINCT FROM 'completed' OR facts->>'storage_state' IS DISTINCT FROM 'verified' OR NOT COALESCE(facts->>'sha256' ~ '^[a-f0-9]{64}$',false) OR facts->>'version' IS NULL OR NOT COALESCE((facts->>'size')::bigint>0,false)) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public result changed';END IF;
 END IF;
 RETURN step_value;
EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export public projection unavailable';
END $public_step$;

DO $export_reads$
DECLARE signature_value text;d text;anchor text;
BEGIN
 signature_value:='public.zasp_production_security_agent_existing_tests_run_context_core(text,text,text,text)';
 PERFORM public.zasp_sa_export_save(signature_value);d:=pg_get_functiondef(signature_value::regprocedure);
 anchor:='''revoke_integration_connection'',''run_test'',''rerun_test'',''start_attack_lab'')';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export action allowlist predecessor changed';END IF;
 d:=replace(d,anchor,'''revoke_integration_connection'',''run_test'',''rerun_test'',''start_attack_lab'',''create_evidence_export'')');
 anchor:='WHEN ''start_attack_lab'' THEN jsonb_build_object(''target_id'',planned_step->''target_id'',''expected_version'',planned_step->''test_definition_version'')';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export action arguments predecessor changed';END IF;
 EXECUTE replace(d,anchor,anchor||chr(10)||'WHEN ''create_evidence_export'' THEN jsonb_build_object(''target_id'',planned_step->''target_id'',''evidence_ids'',planned_step->''evidence_ids'')');
 signature_value:='public.zasp_production_security_agent_existing_tests_public_step(text,text,text,text,jsonb)';
 PERFORM public.zasp_sa_export_save(signature_value);d:=pg_get_functiondef(signature_value::regprocedure);
 anchor:=' SELECT * INTO link_row FROM public.zasp_security_agent_test_links';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export action public predecessor changed';END IF;
 EXECUTE replace(d,anchor,' IF step_value->>''action''=''create_evidence_export'' THEN RETURN public.zasp_sa_export_public_step(o,w,e,r,step_value);END IF;'||chr(10)||anchor);
END $export_reads$;

CREATE FUNCTION public.zasp_sa_export_api_require(expected_checksum text,expected_fingerprint text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $require$
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_api') OR NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export API authority unavailable';END IF;
END $require$;

-- Preserve the original approval decision's CAS, fresh-auth and immutable
-- idempotency receipt. This projection describes artifact creation, not security
-- verification; "reversible" retains the catalog's artifact-expiry semantics.
CREATE FUNCTION public.zasp_sa_export_approval_value(o text,w text,e text,a text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $approval$
DECLARE approval public.zasp_security_agent_approvals%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;st public.zasp_security_agent_steps%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;item jsonb;l public.zasp_sa_export_links%ROWTYPE;
BEGIN
 SELECT * INTO STRICT approval FROM public.zasp_security_agent_approvals WHERE (organization_id,workspace_id,environment_id,approval_id)=(o,w,e,a);
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,approval.run_id);
 SELECT * INTO STRICT st FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id,action_key)=(o,w,e,rr.run_id,approval.step_id,'create_evidence_export');
 SELECT * INTO STRICT p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id,plan_hash,definition_id,definition_version)=(o,w,e,rr.run_id,approval.plan_hash,rr.definition_id,rr.definition_version);
 item:=p.plan->'steps'->st.step_index;
 PERFORM public.zasp_sa_export_selection(item->'evidence_ids');
 IF rr.plan_hash IS DISTINCT FROM approval.plan_hash OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256')
 OR p.plan->'verification' IS DISTINCT FROM '{"kind":"export"}'::jsonb OR st.authorization_result IS DISTINCT FROM 'approval_required'
 OR item IS DISTINCT FROM jsonb_build_object('index',st.step_index,'step_id',st.step_id,'action','create_evidence_export','target_id',rr.run_id,'evidence_ids',item->'evidence_ids','authorization','approval_required')
 OR st.input_digest IS DISTINCT FROM digest(convert_to(item::text,'UTF8'),'sha256')
 OR approval.requester_id IS DISTINCT FROM rr.requested_by
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export approval plan changed';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,rr.run_id,st.step_id);
 IF FOUND AND (l.plan_hash,l.input_digest,l.selection) IS DISTINCT FROM (p.plan_hash,st.input_digest,item->'evidence_ids') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export approval binding changed';END IF;
 RETURN jsonb_build_object('id',a,'run_id',rr.run_id,'step_id',st.step_id,'state',approval.state,'expires_at',to_char(approval.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'version',approval.version,'expected_effect','Create run-scoped evidence export','reversible',true,'ttl_seconds',0,'evidence_summary',jsonb_build_array(rr.trigger_id));
END $approval$;

DO $export_approvals$
DECLARE sig text;d text;anchor text;
BEGIN
 sig:='public.zasp_production_security_agent_existing_tests_approval_value(text,text,text,text)';
 PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 anchor:=' IF step_row.action_key NOT IN(''run_test'',''rerun_test'') THEN';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export approval predecessor changed';END IF;
 EXECUTE replace(d,anchor,' IF step_row.action_key=''create_evidence_export'' THEN RETURN public.zasp_sa_export_approval_value(o,w,e,a);END IF;'||chr(10)||anchor);
 sig:='public.zasp_production_security_agent_existing_tests_decide_approval(text,text,text,text,text,text,bigint,text,timestamptz,text,text,text,text,text)';
 PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 anchor:='IF action_value IS DISTINCT FROM ''run_test'' AND action_value IS DISTINCT FROM ''rerun_test'' THEN';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export decision predecessor changed';END IF;
 EXECUTE replace(d,anchor,'IF action_value IS DISTINCT FROM ''run_test'' AND action_value IS DISTINCT FROM ''rerun_test'' AND action_value IS DISTINCT FROM ''create_evidence_export'' THEN');
END $export_approvals$;

-- Routing confers no dispatch, budget or upload authority. After a committed
-- lease-clearing dispatch only an existing family's durable receipt can route.
-- Existing-test dispatch has no such receipt, so its predecessor refusal stays.
CREATE FUNCTION public.zasp_sa_export_run_kind(o text,w text,e text,r text,worker_value text,lease_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $kind$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;prior public.zasp_sa_attack_lab_links%ROWTYPE;p public.zasp_security_agent_plans%ROWTYPE;d public.zasp_security_agent_definition_versions%ROWTYPE;is_export boolean;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_worker') OR NOT public.zasp_sa_export_guard() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export route authority unavailable';END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY[o,w,e,r]) id WHERE NOT COALESCE(public.zasp_valid_product_id(id),false)) OR NOT COALESCE(length(worker_value) BETWEEN 1 AND 128 AND length(lease_value) BETWEEN 16 AND 128,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export route identity rejected';END IF;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export route parent unavailable';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  IF (l.dispatch_worker,l.dispatch_token_digest) IS DISTINCT FROM (worker_value,digest(lease_value,'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route replay identity changed';END IF;
  PERFORM public.zasp_sa_export_authorize(o,w,e,r,l.step_id,'retrieve');RETURN jsonb_build_object('export',true);
 END IF;
 SELECT * INTO prior FROM public.zasp_sa_attack_lab_links WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  IF prior.dispatch_worker IS DISTINCT FROM worker_value OR prior.dispatch_lease_digest IS DISTINCT FROM digest(convert_to(lease_value,'UTF8'),'sha256')
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_plans replay_plan JOIN public.zasp_security_agent_steps s USING(organization_id,workspace_id,environment_id,run_id) JOIN public.zasp_security_agent_approvals a USING(organization_id,workspace_id,environment_id,run_id,step_id)
    WHERE (replay_plan.organization_id,replay_plan.workspace_id,replay_plan.environment_id,replay_plan.run_id,s.step_id)=(o,w,e,r,prior.step_id) AND replay_plan.plan_hash=prior.plan_hash AND digest(convert_to(replay_plan.plan::text,'UTF8'),'sha256')=prior.plan_hash AND s.input_digest=prior.input_digest AND replay_plan.plan->'steps'->0=prior.intent->'step' AND a.approval_id=prior.approval_id AND a.version=(prior.intent->>'approval_version')::bigint AND a.approver_id=prior.approver_id AND a.requester_id=prior.requester_id AND a.plan_hash=prior.plan_hash AND to_jsonb(a.fresh_auth_at)=prior.intent->'fresh_auth_at' AND a.state='approved') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route attack lab replay changed';END IF;
  RETURN jsonb_build_object('export',false);
 END IF;
 IF rr.state IS DISTINCT FROM 'planning' OR (rr.lease_owner,rr.lease_token) IS DISTINCT FROM (worker_value,lease_value) OR rr.lease_expires_at IS NULL OR rr.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route lease lost';END IF;
 SELECT * INTO STRICT d FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version);
 IF d.definition_digest IS DISTINCT FROM digest(convert_to(d.definition::text,'UTF8'),'sha256') OR jsonb_typeof(d.definition->'allowed_actions') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route definition changed';END IF;
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF FOUND THEN
  IF (p.plan_hash,p.definition_id,p.definition_version) IS DISTINCT FROM (rr.plan_hash,rr.definition_id,rr.definition_version) OR p.plan_hash IS DISTINCT FROM digest(convert_to(p.plan::text,'UTF8'),'sha256') OR jsonb_typeof(p.plan->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(p.plan->'steps')=0 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route plan changed';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(p.plan->'steps') WITH ORDINALITY item(value,position) WHERE NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_steps s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_index)=(o,w,e,r,item.position-1) AND s.step_id=item.value->>'step_id' AND s.action_key=item.value->>'action' AND s.input_digest=digest(convert_to(item.value::text,'UTF8'),'sha256'))) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route step changed';END IF;
  is_export:=EXISTS(SELECT 1 FROM jsonb_array_elements(p.plan->'steps') item WHERE item->>'action'='create_evidence_export');
 ELSE
  IF rr.plan_hash IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export route plan unavailable';END IF;
  is_export:=d.definition->'allowed_actions' ? 'create_evidence_export';
 END IF;
 RETURN jsonb_build_object('export',is_export);
END $kind$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_export_run_kind(text,text,text,text,text,text) TO zasp_security_agent_worker;

CREATE FUNCTION public.zasp_sa_export_browser(o text,w text,e text,actor text,session_value bytea,csrf_value text,id_value text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $browser$
DECLARE ss public.zasp_product_sessions%ROWTYPE;l public.zasp_sa_export_links%ROWTYPE;
BEGIN
 SELECT * INTO ss FROM public.zasp_product_sessions WHERE token_digest=session_value AND (organization_id,workspace_id,environment_id,principal_id)=(o,w,e,actor) FOR SHARE;
 IF NOT FOUND OR ss.revoked_at IS NOT NULL OR ss.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='export browser session rejected';END IF;
 IF csrf_value IS NULL OR octet_length(csrf_value)<32 OR ss.csrf_token IS DISTINCT FROM csrf_value THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export browser authorization rejected';END IF;
 PERFORM 1 FROM public.zasp_identity_memberships WHERE (organization_id,principal_id,active)=(o,actor,true) FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export browser membership rejected';END IF;
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,export_id)=(o,w,e,id_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export browser binding rejected';END IF;
 PERFORM public.zasp_sa_export_authorize(o,w,e,l.run_id,l.step_id,'retrieve');
 PERFORM public.zasp_sa_export_source_permissions(o,w,e,actor,l.selection);
 IF ss.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='28000',MESSAGE='export browser session expired';END IF;
END $browser$;

CREATE FUNCTION public.zasp_sa_export_get(o text,w text,e text,r text,s text,principal_value text,session_value bytea,csrf_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $get$
DECLARE l public.zasp_sa_export_links%ROWTYPE;j public.zasp_compliance_export_jobs%ROWTYPE;
BEGIN
 PERFORM public.zasp_sa_export_api_require(expected_checksum,expected_fingerprint);
 SELECT * INTO l FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export scoped link unavailable';END IF;
 PERFORM public.zasp_sa_export_browser(o,w,e,principal_value,session_value,csrf_value,l.export_id);
 SELECT * INTO STRICT j FROM public.zasp_compliance_export_jobs WHERE (organization_id,workspace_id,environment_id,export_id,job_origin,agent_run_id,agent_step_id)=(o,w,e,l.export_id,'agent_run',r,s) FOR SHARE;
 PERFORM public.zasp_sa_export_browser(o,w,e,principal_value,session_value,csrf_value,l.export_id);
 RETURN jsonb_build_object('export_id',j.export_id,'state',j.state,'phase',j.phase,'failure_code',j.failure_code,'created_at',j.created_at,'retrieval_expires_at',j.retrieval_expires_at,'mapping_revision',j.mapping_revision,'snapshot_at',j.snapshot_at,
  'cleanup_state',CASE WHEN j.storage_state='deleted' THEN 'deleted' WHEN j.storage_state IN('unknown','reconcile_required','delete_pending') THEN 'pending' ELSE 'retained' END,'selection',l.selection,'artifact',CASE WHEN j.artifact_digest IS NULL OR j.artifact_size IS NULL THEN NULL ELSE jsonb_build_object('sha256',encode(j.artifact_digest,'hex'),'size',j.artifact_size) END);
END $get$;

-- Reuse the exact shared grant lifecycle and tables. Only origin/identity and
-- current source authorization differ; expiry, quotas and read leases do not.
DO $grant_core$
DECLARE d text;anchor text;
BEGIN
 d:=pg_get_functiondef('public.zasp_compliance_export_grant(text,text,text,text,bytea,text,text,text,text,text,text)'::regprocedure);
 d:=replace(d,'FUNCTION public.zasp_compliance_export_grant(','FUNCTION zasp_sa_export_prior.grant_core(');
 anchor:='expected_fingerprint text)';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export grant signature changed';END IF;
 d:=replace(d,anchor,'expected_fingerprint text, csrf_value text)');
 anchor:='PERFORM public.zasp_compliance_require(expected_checksum,expected_fingerprint,''zasp_discovery_api'');';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export grant authority changed';END IF;
 d:=replace(d,anchor,'PERFORM public.zasp_sa_export_api_require(expected_checksum,expected_fingerprint);');
 anchor:='PERFORM public.zasp_compliance_export_identity(org_value,workspace_value,environment_value,principal_value,session_value);';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export grant browser changed';END IF;
 d:=replace(d,anchor,'PERFORM public.zasp_sa_export_browser(org_value,workspace_value,environment_value,principal_value,session_value,csrf_value,id_value);');
 anchor:='(organization_id,workspace_id,environment_id,export_id,principal_id)=(org_value,workspace_value,environment_value,id_value,principal_value) FOR UPDATE';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export grant origin changed';END IF;
 d:=replace(d,anchor,'(organization_id,workspace_id,environment_id,export_id)=(org_value,workspace_value,environment_value,id_value) AND job_origin=''agent_run'' FOR UPDATE');
 anchor:='''read_expires_at'',g.read_expires_at) ELSE';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export grant receipt changed';END IF;
 d:=replace(d,anchor,'''read_expires_at'',g.read_expires_at,''binding'',(SELECT jsonb_build_object(''run_id'',l.run_id,''step_id'',l.step_id,''selection'',l.selection) FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.export_id)=(org_value,workspace_value,environment_value,id_value))) ELSE');
 EXECUTE d;
 ALTER FUNCTION zasp_sa_export_prior.grant_core(text,text,text,text,bytea,text,text,text,text,text,text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_sa_export_prior.grant_core(text,text,text,text,bytea,text,text,text,text,text,text,text) FROM PUBLIC;
END $grant_core$;

CREATE FUNCTION public.zasp_sa_export_grant(o text,w text,e text,r text,s text,principal_value text,session_value bytea,csrf_value text,token_value text,format_value text,operation_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $grant$
DECLARE id_value text;
BEGIN
 PERFORM public.zasp_sa_export_api_require(expected_checksum,expected_fingerprint);
 SELECT export_id INTO id_value FROM public.zasp_sa_export_links WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(o,w,e,r,s);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export scoped grant unavailable';END IF;
 RETURN zasp_sa_export_prior.grant_core(o,w,e,principal_value,session_value,id_value,token_value,format_value,operation_value,expected_checksum,expected_fingerprint,csrf_value);
END $grant$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_export_get(text,text,text,text,text,text,bytea,text,text,text),public.zasp_sa_export_grant(text,text,text,text,text,text,bytea,text,text,text,text,text,text) TO zasp_security_agent_api;

DO $browser_origin$
DECLARE sig text;d text;anchor text;
BEGIN
 FOREACH sig IN ARRAY ARRAY['public.zasp_compliance_export_create(text,text,text,text,bytea,text,jsonb,text,text)','public.zasp_compliance_export_get(text,text,text,text,bytea,text,text,text)','public.zasp_compliance_export_grant(text,text,text,text,bytea,text,text,text,text,text,text)'] LOOP
  PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
  IF starts_with(sig,'public.zasp_compliance_export_create(') THEN anchor:='(organization_id,workspace_id,environment_id,principal_id,idempotency_key)=(org_value,workspace_value,environment_value,principal_value,key_value)';
  ELSE anchor:='(organization_id,workspace_id,environment_id,export_id,principal_id)=(org_value,workspace_value,environment_value,id_value,principal_value)';END IF;
  IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='browser origin predecessor changed';END IF;
  EXECUTE replace(d,anchor,anchor||' AND job_origin=''browser''');
 END LOOP;
END $browser_origin$;

CREATE FUNCTION public.zasp_sa_export_cancel_child(o text,w text,e text,r text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $cancel_child$
BEGIN
 -- The caller owns the parent row before taking a job row. An admitted PUT
 -- may still be in flight; intent must retain quota and reconciliation duty.
 UPDATE public.zasp_compliance_export_jobs SET state=CASE WHEN state='pending' THEN 'failed' ELSE state END,phase='terminal',failure_code=CASE WHEN state='pending' THEN 'export_cancelled' ELSE failure_code END,
  storage_state=CASE WHEN package IS NOT NULL AND receipt_version IS NULL THEN 'reconcile_required' ELSE storage_state END,
  retrieval_expires_at=least(retrieval_expires_at,clock_timestamp()),lease_expires_at=NULL,lease_digest=NULL,next_attempt_at=clock_timestamp()
 WHERE (organization_id,workspace_id,environment_id,job_origin,agent_run_id)=(o,w,e,'agent_run',r);
END $cancel_child$;

DO $parent_cancellation$
DECLARE sig text:='public.zasp_security_agent_cancel_run(text,text,text,text,text,text,bigint,text,text,text)';d text;anchor text;
BEGIN
 PERFORM public.zasp_sa_export_save(sig);d:=pg_get_functiondef(sig::regprocedure);
 anchor:='EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value))';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export cancellation predecessor changed';END IF;
 d:=replace(d,anchor,'EXISTS(SELECT 1 FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(organization_value,workspace_value,environment_value,run_value) AND NOT (effect.action_key=''create_evidence_export'' AND EXISTS(SELECT 1 FROM public.zasp_sa_export_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.input_digest,l.export_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.input_digest,effect.outcome_id))))');
 anchor:='  UPDATE zasp_security_agent_approvals approval SET state=''cancelled''';
 IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='export cancellation update changed';END IF;
 d:=replace(d,anchor,'  PERFORM public.zasp_sa_export_cancel_child(organization_value,workspace_value,environment_value,run_value);'||chr(10)||anchor);
 EXECUTE d;
END $parent_cancellation$;
