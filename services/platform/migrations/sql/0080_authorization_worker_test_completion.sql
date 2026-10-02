-- Keep the adapter's existing parent-lock role and RLS untouched. Captured
-- settlement uses the already permitted compensation parent visibility.
DO $captured_identity$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal74.lock_identity(text,text,text,text,text,text)'::regprocedure) INTO d;
 d:=replace(d,'FUNCTION zasp_temporal74.lock_identity(','FUNCTION zasp_authorization80_worker.test74_captured_identity(');
 needle:='zasp_temporal68.adapter_principal_ready()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker captured identity predecessor changed';END IF;
 EXECUTE replace(d,needle,$comp$zasp_temporal68.principal_ready('zasp_temporal_compensation')$comp$);
END $captured_identity$;
CREATE FUNCTION zasp_authorization80_worker.test74_captured_parent(o text,w text,e text,r text,c text,k text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $captured_parent$
DECLARE result_value jsonb;BEGIN
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.test74_captured_identity(o,w,e,r,c,k) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured parent rejected';END IF;
 SELECT to_jsonb(rr) INTO STRICT result_value FROM public.zasp_security_agent_runs rr WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.test74_captured_identity(o,w,e,r,c,k) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured parent changed';END IF;
 RETURN result_value;
END $captured_parent$;

CREATE FUNCTION zasp_authorization80_worker.test74_completion_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $completion_source$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;a zasp_authorization80_worker.test_associations%ROWTYPE;v zasp_temporal74.effects%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;j zasp_temporal74.invocations%ROWTYPE;
 f jsonb;parent_value jsonb;reference_value jsonb;journal_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker completion requires read committed';END IF;
 IF NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker completion role rejected';END IF;
 IF phase IS DISTINCT FROM 'complete' OR q->>'operation' IS DISTINCT FROM phase OR octet_length(q::text)>8192
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','effect_key','operation','payload','checksum','fingerprint'])
 OR NOT COALESCE(zasp_temporal74.ready(q->>'checksum',q->>'fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker completion request rejected';END IF;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,test_run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker completion owner rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 parent_value:=zasp_authorization80_worker.test74_captured_parent(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.test_run_id,q->>'effect_key');
 reference_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 f:=zasp_authorization80_worker.test74_native_facts(true,reference_value,true);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker completion capture absent';END IF;
 SELECT * INTO v FROM zasp_temporal74.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1,q->>'effect_key') FOR SHARE;
 SELECT * INTO i FROM zasp_temporal74.test_inputs WHERE(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id) FOR SHARE;
 SELECT * INTO j FROM zasp_temporal74.invocations WHERE(organization_id,workspace_id,environment_id,test_run_id,category)=(x.organization_id,x.workspace_id,x.environment_id,x.test_run_id,q#>>'{payload,category}') FOR SHARE;
 IF v.run_id IS NULL OR i.run_id IS NULL OR j.test_run_id IS NULL OR j.state NOT IN('started','completed') OR j.attempt<>1
 OR j.effect_key IS DISTINCT FROM v.effect_key OR j.target_resolution IS DISTINCT FROM v.snapshot->'targets'->'resolution'
 OR encode(j.request_digest,'hex') IS DISTINCT FROM q#>>'{payload,request_digest}'
 OR encode(j.input_digest,'hex') IS DISTINCT FROM v.snapshot#>>'{targets,input_digest}'
 OR encode(digest(convert_to((v.snapshot->'targets'->'resolution')::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM a.target_digest
 OR NOT zasp_temporal74.test_intent_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,parent_value) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured invocation rejected';END IF;
 -- Timestamp rendering is explicit for this new proof, independent of caller
 -- timezone. The retained journal and native validators are not rewritten.
 journal_value:=(to_jsonb(j)-ARRAY['started_at','completed_at'])||jsonb_build_object('started_at',to_char(j.started_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
 RETURN f||jsonb_build_object('completion_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'child_run_id',x.test_run_id,'step_id',x.step_id,'effect_key',v.effect_key,'generation',v.generation,'snapshot_digest',encode(v.snapshot_digest,'hex'),'input_digest',encode(j.input_digest,'hex'),'manifest_digest',encode(digest(convert_to(i.manifest::text,'UTF8'),'sha256'),'hex'),'body_digest',encode(digest(i.body,'sha256'),'hex'),'journal_digest',encode(digest(convert_to(journal_value::text,'UTF8'),'sha256'),'hex'));
END $completion_source$;

DO $completion_body$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning74(text,jsonb)'::regprocedure) INTO d;
 d:=replace(replace(replace(d,'require_planning74','require_test74_completion'),'planning74_source','test74_completion_source'),'test74.planning.','test74.adapter.');
 needle:=$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion phase predecessor changed';END IF;
 d:=replace(d,needle,$new$('complete')$new$);
 needle:=$old$CASE WHEN phase IN('reconcile','late_usage','recovery') THEN 'captured-compensation' ELSE 'worker-forward' END$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion purpose predecessor changed';END IF;
 EXECUTE replace(d,needle,$new$'captured-compensation'$new$);
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.invocation(jsonb)' AND owner_name='zasp_discovery_authority';
 d:=replace(d,'FUNCTION zasp_temporal74.invocation(q jsonb)','FUNCTION zasp_authorization80_worker.test74_complete(q jsonb)');
 needle:=E'BEGIN\n';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion entry predecessor changed';END IF;
 d:=replace(d,needle,needle||$fence$ PERFORM zasp_authorization80_worker.require_test74_completion(q->>'operation',q);$fence$||E'\n');
 needle:='zasp_temporal68.adapter_principal_ready()';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion role predecessor changed';END IF;
 d:=replace(d,needle,$new$zasp_temporal68.principal_ready('zasp_temporal_compensation')$new$);
 needle:=$old$zasp_temporal74.adapter_ready(q->>'checksum',q->>'fingerprint')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion readiness predecessor changed';END IF;
 d:=replace(d,needle,$new$(zasp_temporal74.ready(q->>'checksum',q->>'fingerprint') AND zasp_temporal68.principal_ready('zasp_temporal_compensation'))$new$);
 needle:='parent_value:=zasp_temporal74.lock_parent(o,w,e,link.run_id,child_id,key_value);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion parent predecessor changed';END IF;
 d:=replace(d,needle,'parent_value:=zasp_authorization80_worker.test74_captured_parent(o,w,e,link.run_id,child_id,key_value);');
 needle:=' RETURN result_value;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker completion receipt predecessor changed';END IF;
 EXECUTE replace(d,needle,$receipt$ RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'parent_run_id',link.run_id,'test_run_id',child_id,'step_id',link.step_id,'effect_key',j.effect_key,'category',category_value,'attempt',j.attempt,'state',j.state,'request_digest',encode(j.request_digest,'hex'),'response_digest',encode(j.response_digest,'hex'),'http_status',j.http_status,'protected',j.protected,'credential_version_digest',encode(j.credential_version_digest,'hex'),'completed_at',to_char(j.completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));$receipt$);
END $completion_body$;
