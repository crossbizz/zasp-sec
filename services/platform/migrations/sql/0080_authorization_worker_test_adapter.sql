-- Adapter readers have their own registered-session gates and grants. They do
-- not inherit the executor reader's authority or broaden parent-row visibility.
CREATE FUNCTION zasp_authorization80_worker.adapter_revision(o text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $adapter_revision$
BEGIN
 IF NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.adapter_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter revision reader rejected';END IF;
 RETURN(SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) FROM zasp_authorization79.organizations WHERE organization_id=o);
END $adapter_revision$;
CREATE FUNCTION zasp_authorization80_worker.adapter_key_ready(p text,v text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $adapter_key$
 SELECT COALESCE(p='worker-forward' AND zasp_temporal74.current_ready() AND zasp_authorization80_worker.catalog_ready() AND zasp_temporal68.adapter_principal_ready() AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.verifiers WHERE purpose=p AND version=v),false)
$adapter_key$;

CREATE FUNCTION zasp_authorization80_worker.adapter74_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $adapter_source$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;a zasp_authorization80_worker.test_associations%ROWTYPE;v zasp_temporal74.effects%ROWTYPE;i zasp_temporal74.test_inputs%ROWTYPE;
 f jsonb;parent_value jsonb;reference_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='worker adapter requires read committed';END IF;
 IF NOT zasp_temporal68.adapter_principal_ready() OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter source role rejected';END IF;
 IF phase IS NULL OR phase NOT IN('resolve','start') OR q->>'operation' IS DISTINCT FROM phase OR octet_length(q::text)>8192
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','effect_key','operation','payload','checksum','fingerprint'])
 OR NOT COALESCE(zasp_temporal74.adapter_ready(q->>'checksum',q->>'fingerprint'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker adapter request rejected';END IF;
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,test_run_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id');
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter owner rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 parent_value:=zasp_temporal74.lock_parent(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.test_run_id,q->>'effect_key');
 reference_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 f:=zasp_authorization80_worker.test74_private_facts(false,reference_value,true,parent_value);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker adapter association rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) AND s.target_current AND s.fresh_until>clock_timestamp()) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker adapter capture changed';END IF;
 PERFORM zasp_temporal74.step_parent(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,parent_value);
 SELECT * INTO v FROM zasp_temporal74.effects WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation,effect_key)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1,q->>'effect_key') FOR SHARE;
 SELECT * INTO i FROM zasp_temporal74.test_inputs WHERE(organization_id,workspace_id,environment_id,run_id,step_id,test_run_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,x.test_run_id) FOR SHARE;
 IF v.run_id IS NULL OR i.run_id IS NULL OR NOT zasp_temporal74.test_intent_valid(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,parent_value)
 OR encode(digest(convert_to((v.snapshot->'targets'->'resolution')::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM a.target_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker adapter native identity changed';END IF;
 RETURN f||jsonb_build_object('adapter_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'child_run_id',x.test_run_id,'step_id',x.step_id,'effect_key',v.effect_key,'generation',v.generation,'effect_state',v.state,'snapshot_digest',encode(v.snapshot_digest,'hex'),'input_digest',encode(v.input_digest,'hex'),'plan_hash',encode(v.plan_hash,'hex'),'manifest_digest',encode(digest(convert_to(i.manifest::text,'UTF8'),'sha256'),'hex'),'body_digest',encode(digest(i.body,'sha256'),'hex'));
END $adapter_source$;

DO $adapter_proof$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning74(text,jsonb)'::regprocedure) INTO d;
 d:=replace(replace(replace(d,'require_planning74','require_adapter74'),'planning74_source','adapter74_source'),'test74.planning.','test74.adapter.');
 needle:=$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker adapter proof phase predecessor changed';END IF;
 d:=replace(d,needle,$new$('resolve','start')$new$);
 needle:=$old$CASE WHEN phase IN('reconcile','late_usage','recovery') THEN 'captured-compensation' ELSE 'worker-forward' END$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker adapter proof purpose predecessor changed';END IF;
 d:=replace(d,needle,$new$'worker-forward'$new$);
 needle:=$old$zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END)$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker adapter proof role predecessor changed';END IF;
 EXECUTE replace(d,needle,'zasp_temporal68.adapter_principal_ready()');
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.invocation(jsonb)';
 needle:=E'BEGIN\n';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker adapter invocation predecessor changed';END IF;
 EXECUTE replace(d,needle,needle||$fence$ PERFORM zasp_authorization80_worker.require_adapter74(q->>'operation',q);$fence$||E'\n');
END $adapter_proof$;
