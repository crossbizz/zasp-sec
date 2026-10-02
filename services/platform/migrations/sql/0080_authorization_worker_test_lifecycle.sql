-- A status-only private copy keeps the receipt reader's intent, original input,
-- curated request and existing-row binding checks. There is no write dispatch.
DO $recovery_status_reader$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.test74_receipt_read(jsonb)'::regprocedure);
 d:=replace(d,'FUNCTION zasp_authorization80_worker.test74_receipt_read(q jsonb)','FUNCTION zasp_authorization80_worker.test74_recovery_observation(q jsonb, locked_parent jsonb, captured_facts jsonb)');
 -- Only lifecycle_source calls this private reader, after validating these
 -- values under the same parent/schema locks. They never come from a proof.
 needle:=$old$NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker status readiness predecessor changed';END IF;
 d:=replace(d,needle,$new$NOT zasp_temporal68.principal_ready('zasp_temporal_compensation')$new$);
 needle:=$old$(q->>'checksum'='-- worker test checksum' AND q->>'fingerprint'='-- worker test fingerprint')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker status pins predecessor changed';END IF;
 -- Receipt already emits the exact pins; lifecycle retains that predicate.
 needle:='parent_value:=zasp_authorization80_worker.test74_receipt_parent(o,w,e,link.run_id,child_id,key_value);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker status parent predecessor changed';END IF;
 d:=replace(d,needle,$new$IF NOT zasp_authorization80_worker.test74_captured_identity(o,w,e,link.run_id,child_id,key_value) OR (locked_parent->>'organization_id',locked_parent->>'workspace_id',locked_parent->>'environment_id',locked_parent->>'run_id') IS DISTINCT FROM(o,w,e,link.run_id) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker status parent changed';END IF;parent_value:=locked_parent;$new$);
 needle:=$old$facts_value:=zasp_authorization80_worker.test74_native_facts(true,jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',link.run_id,'definition_version',owner_value.definition_version,'input_digest',owner_value.input_digest),true);$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker status facts predecessor changed';END IF;
 d:=replace(d,needle,'facts_value:=captured_facts;');
 needle:='  IF j.test_run_id IS NULL OR j.state IS DISTINCT FROM ''completed''';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker recovery status guard changed';END IF;
 d:=replace(d,needle,$classification$
  IF (link.run_id,link.step_id,encode(child.input_digest,'hex')) IS DISTINCT FROM(reference_value->>'parent_run_id',reference_value->>'step_id',reference_value->>'input_digest') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker recovery input changed';END IF;
  IF j.test_run_id IS NULL OR j.state='started' THEN
   IF j.test_run_id IS NOT NULL AND(j.attempt IS DISTINCT FROM 1 OR j.started_at IS NULL OR j.completed_at IS NOT NULL OR j.http_status IS NOT NULL OR j.response_digest IS NOT NULL OR j.protected IS NOT NULL OR j.credential_version_digest IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker pending observation malformed';END IF;
   IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker recovery authority changed';END IF;
   journal_value:=(to_jsonb(j)-ARRAY['started_at','completed_at'])||jsonb_build_object('started_at',to_char(j.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',NULL);
   RETURN jsonb_build_object('status','pending','journal_digest',encode(digest(convert_to(journal_value::text,'UTF8'),'sha256'),'hex'));
  END IF;
  IF j.test_run_id IS NULL OR j.state IS DISTINCT FROM 'completed'$classification$);
 needle:=$old$RETURN jsonb_build_object('facts',facts_value,'receipt',result_value);$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker recovery status return changed';END IF;
 EXECUTE replace(d,needle,$new$RETURN jsonb_build_object('status','complete','journal_digest',facts_value->'journal_digest');$new$);
END $recovery_status_reader$;

CREATE FUNCTION zasp_authorization80_worker.test74_recovery_status_facts(q jsonb,locked_parent jsonb,captured_facts jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $status_facts$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;f zasp_temporal74.effects%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;l public.zasp_security_agent_test_links%ROWTYPE;a zasp_authorization80_worker.test_associations%ROWTYPE;
 category_value text;curated text;observation jsonb;observations jsonb:='[]';status_value text:='complete';
BEGIN
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker recovery status role rejected';END IF;
 x:=zasp_temporal74.start_identity(q);
 SELECT * INTO STRICT a FROM zasp_authorization80_worker.test_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 SELECT * INTO STRICT f FROM zasp_temporal74.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1) FOR UPDATE;
 SELECT * INTO STRICT i FROM zasp_temporal74.test_inputs WHERE(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id) FOR SHARE;
 SELECT * INTO STRICT l FROM public.zasp_security_agent_test_links WHERE(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id) FOR SHARE;
 IF f.state NOT IN('started','unknown') OR encode(digest(convert_to((f.snapshot#>'{targets,resolution}')::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM a.target_digest
 OR NOT EXISTS(SELECT 1 FROM zasp_temporal74.planning_jobs WHERE(organization_id,workspace_id,environment_id,run_id,state)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'admitted'))
 OR jsonb_typeof(l.test_categories) IS DISTINCT FROM 'array' OR jsonb_array_length(l.test_categories) NOT BETWEEN 1 AND 6
 OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(l.test_categories))<>jsonb_array_length(l.test_categories)
 OR EXISTS(SELECT 1 FROM zasp_temporal74.invocations j WHERE(j.organization_id,j.workspace_id,j.environment_id,j.test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id) AND NOT l.test_categories ? j.category)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker recovery status capture changed';END IF;
 FOR category_value IN SELECT jsonb_array_elements_text(l.test_categories) LOOP
  curated:='{"schema_version":"red-team-target-v1","run_id":"'||x.test_run_id||'","target_id":"'||l.target_id||'","target_kind":"'||l.target_kind||'","category":"'||category_value||'","input":'||to_json(zasp_sa_multistep_prior.test_prompt(category_value))::text||'}';
  observation:=zasp_authorization80_worker.test74_recovery_observation(jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'parent_run_id',x.run_id,'test_run_id',x.test_run_id,'step_id',x.step_id,'effect_key',f.effect_key,'generation',1,'category',category_value,'input_digest',f.snapshot#>>'{targets,input_digest}','request_digest',encode(digest(convert_to(curated,'UTF8'),'sha256'),'hex')),locked_parent,captured_facts);
  IF observation->>'status'='pending' THEN status_value:='pending';ELSIF observation->>'status' IS DISTINCT FROM 'complete' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker recovery status invalid';END IF;
  observations:=observations||jsonb_build_array(jsonb_build_object('category',category_value,'observation',observation));
 END LOOP;
 RETURN jsonb_build_object('status',status_value,'status_digest',encode(digest(convert_to(observations::text,'UTF8'),'sha256'),'hex'),'snapshot_digest',encode(f.snapshot_digest,'hex'),'input_digest',f.snapshot#>'{targets,input_digest}','manifest_digest',encode(digest(convert_to(i.manifest::text,'UTF8'),'sha256'),'hex'),'body_digest',encode(digest(i.body,'sha256'),'hex'));
END $status_facts$;

-- Captured lifecycle authority is not a fresh delegation. In particular, the
-- native owner can be cancelled before planning has materialized an association.
CREATE FUNCTION zasp_authorization80_worker.test74_lifecycle_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $lifecycle_source$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;r public.zasp_security_agent_runs%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
 a zasp_authorization80_worker.test_associations%ROWTYPE;reference_value jsonb;f jsonb;state_value jsonb;stop_value jsonb;parent_value jsonb;job_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker lifecycle requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker lifecycle principal rejected';END IF;
 IF phase IS NULL OR phase NOT IN('inspect','cleanup','recovery_status') OR octet_length(q::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker lifecycle phase rejected';END IF;
 reference_value:=q;
 IF phase='cleanup' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','reason']) OR NOT COALESCE(q->>'reason' IN('terminal','workflow_cancelled','workflow_deadline','workflow_failed'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker lifecycle cleanup rejected';END IF;
  reference_value:=q-'reason';
 END IF;
 x:=zasp_temporal74.start_identity(reference_value);
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 SELECT * INTO STRICT r FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR UPDATE;
 SELECT * INTO STRICT h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(x.organization_id,x.workspace_id,x.environment_id,x.definition_id,x.definition_version) FOR SHARE;
 IF (r.definition_id,r.definition_version) IS DISTINCT FROM(x.definition_id,x.definition_version)
 OR x.source_kind NOT IN('manual65','automatic73') OR x.action_key NOT IN('run_test','rerun_test')
 OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256')
 OR h.definition->'allowed_actions' IS DISTINCT FROM jsonb_build_array(x.action_key)
 OR x.step_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_step',x.run_id||chr(31)||'0')
 OR x.test_run_id IS DISTINCT FROM public.zasp_discovery_canonical_id(x.organization_id,x.workspace_id,x.environment_id,'security_agent_test_run',x.run_id||chr(31)||x.step_id||chr(31)||x.action_key)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker lifecycle ancestry changed';END IF;
 SELECT * INTO a FROM zasp_authorization80_worker.test_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
 IF a.run_id IS NULL THEN
  IF NOT zasp_temporal74.queued_absent(x.organization_id,x.workspace_id,x.environment_id,x.run_id) OR r.state NOT IN('queued','cancelled') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker lifecycle capture absent';END IF;
  f:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_id',x.definition_id,'definition_version',x.definition_version,'definition_digest',encode(h.definition_digest,'hex'),'source_digest',encode(digest(convert_to((to_jsonb(x)-'transferred_at')::text,'UTF8'),'sha256'),'hex'),'checks','[]'::jsonb,'session_user',session_user);
 ELSE
  f:=zasp_authorization80_worker.test74_native_facts(true,reference_value,true);
  IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.definition_id,x.definition_version,r.state,r.version,true)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker lifecycle capture changed';END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM zasp_temporal74.stops WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN stop_value:=zasp_authorization80_worker.test74_stop_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id);END IF;
 IF EXISTS(SELECT 1 FROM zasp_temporal74.parent_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id)) THEN parent_value:=zasp_temporal74.parent_evidence(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id);END IF;
 SELECT to_jsonb(zasp_authorization80_worker.planner_job_digest(to_jsonb(j))) INTO job_value FROM zasp_temporal74.planning_jobs j WHERE(j.organization_id,j.workspace_id,j.environment_id,j.run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id) FOR SHARE;
 SELECT jsonb_build_object('state',v.state,'generation',v.generation,'effect_key',v.effect_key,'input_digest',encode(v.input_digest,'hex'),'snapshot_digest',encode(v.snapshot_digest,'hex')) INTO state_value FROM zasp_temporal74.effects v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id,v.step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id) FOR SHARE;
 IF phase='recovery_status' THEN f:=f||jsonb_build_object('recovery',zasp_authorization80_worker.test74_recovery_status_facts(reference_value,to_jsonb(r),f));END IF;
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker lifecycle authority changed';END IF;
 RETURN f||jsonb_build_object('lifecycle_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'run_state',r.state,'run_version',r.version,'step_id',x.step_id,'child_run_id',x.test_run_id,'action_key',x.action_key,'job_digest',job_value,'effect',state_value,'stop_digest',encode(digest(convert_to(stop_value::text,'UTF8'),'sha256'),'hex'),'parent_digest',encode(digest(convert_to(parent_value::text,'UTF8'),'sha256'),'hex'));
END $lifecycle_source$;

DO $lifecycle_boundaries$ DECLARE d text;needle text;p record;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.require_test74_completion(text,jsonb)'::regprocedure);
 d:=replace(replace(replace(d,'require_test74_completion','require_test74_lifecycle'),'test74_completion_source','test74_lifecycle_source'),'test74.adapter.','test74.lifecycle.');
 needle:=$old$('complete')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle proof predecessor changed';END IF;
 d:=replace(d,needle,$new$('inspect','cleanup','recovery_status')$new$);
 needle:='RETURNS void';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle return predecessor changed';END IF;
 d:=replace(d,needle,'RETURNS jsonb');
 -- The inherited source is computed once under locks. Its fresh-clock fence
 -- precedes equality and this return, including every recovery-status path.
 needle:=$old$IF proof->'facts' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning source changed';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle source predecessor changed';END IF;
 EXECUTE replace(d,needle,needle||'RETURN source_value;');
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal74.inspect(jsonb)','zasp_temporal74.cleanup(jsonb)') LOOP
  d:=p.definition;needle:=E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n';
  IF p.owner_name<>'zasp_discovery_authority' OR(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle native predecessor changed';END IF;
  IF p.signature='zasp_temporal74.inspect(jsonb)' THEN
   EXECUTE replace(d,'FUNCTION zasp_temporal74.inspect(q jsonb)','FUNCTION zasp_authorization80_worker.test74_inspect(q jsonb)');
   d:=replace(d,needle,needle||$fence$ PERFORM zasp_authorization80_worker.require_test74_lifecycle('inspect',q);$fence$||E'\n');
  ELSE
   d:=replace(d,needle,needle||$fence$ PERFORM zasp_authorization80_worker.require_test74_lifecycle('cleanup',q);$fence$||E'\n');
   needle:='PERFORM zasp_temporal74.plan(request_value)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle planning recovery changed';END IF;
   d:=replace(d,needle,'PERFORM zasp_temporal74.recover_plan(request_value)');
   needle:='PERFORM zasp_temporal74.effect(request_value)';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker lifecycle captured effect changed';END IF;
   d:=replace(d,needle,'PERFORM zasp_authorization80_worker.test74_effect(request_value)');
  END IF;
  EXECUTE d;
 END LOOP;
END $lifecycle_boundaries$;

CREATE FUNCTION zasp_authorization80_worker.test74_recovery_status(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $status$
DECLARE f jsonb;BEGIN
 f:=zasp_authorization80_worker.require_test74_lifecycle('recovery_status',q);
 RETURN jsonb_build_object('status',f#>'{recovery,status}');
END $status$;
