-- The current human proof is checked before entering retained native mutation.
-- The private marker authenticates only this transaction's exact invocation,
-- not arbitrary caller-selected revision increases or later raw DML.
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_clear() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $clear$
BEGIN
 PERFORM set_config('zasp.discovery72_human','',true);PERFORM set_config('zasp.discovery72_human_seal','',true);
END $clear$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_marker() RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $marker$
DECLARE m jsonb;p jsonb;seal text;expected_seal text;BEGIN
 m:=NULLIF(current_setting('zasp.discovery72_human',true),'')::jsonb;p:=zasp_authorization80.context();
 seal:=NULLIF(current_setting('zasp.discovery72_human_seal',true),'');expected_seal:=zasp_authorization80.context_seal(m);
 IF m IS NULL OR p IS NULL OR m->>'domain' IS DISTINCT FROM 'discovery72-human-v1'
 OR seal IS NULL OR expected_seal IS NULL OR seal IS DISTINCT FROM expected_seal
 OR m->>'proof_digest' IS DISTINCT FROM encode(digest(convert_to(p::text,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery human invocation rejected';END IF;
 RETURN m;
EXCEPTION WHEN data_exception THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery human invocation rejected';
END $marker$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_save(m jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $save$
BEGIN
 PERFORM set_config('zasp.discovery72_human',m::text,true);PERFORM set_config('zasp.discovery72_human_seal',zasp_authorization80.context_seal(m),true);
END $save$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_check(m jsonb,delta bigint) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $check$
DECLARE p jsonb:=zasp_authorization80.context();target_version bigint;BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal72.current_ready()
 OR p IS NULL OR NOT EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE authority_role='zasp_discovery_api' AND principal_name=session_user)
 OR NOT COALESCE(zasp_authorization80.read_request(m->>'organization_id',m->>'workspace_id',m->>'environment_id',ARRAY[m->>'operation'],'manage_workflows',false,m->>'actor')
 AND NOT(p->>'collection')::boolean AND p#>>'{path_parameters,id}'=m->>'integration_id'
 AND zasp_authorization80.allowed(m->>'organization_id',m->>'workspace_id',m->>'environment_id','integration',m->>'integration_id'),false)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery current human authority required';END IF;
 -- The initial fence owns this revision row. Every later check admits only
 -- the measured local mutation delta, with all other pins unchanged.
 PERFORM 1 FROM zasp_authorization79.organizations x WHERE x.organization_id=m->>'organization_id'
 AND(x.desired,x.applied,x.generation,x.store_id,x.model_id)=((p#>>'{revision,desired}')::bigint+delta,(p#>>'{revision,applied}')::bigint,(p#>>'{revision,generation}')::bigint,p#>>'{revision,store_id}',p#>>'{revision,model_id}') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery human revision changed';END IF;
 SELECT version INTO target_version FROM public.zasp_integrations WHERE(organization_id,workspace_id,environment_id,id)=(m->>'organization_id',m->>'workspace_id',m->>'environment_id',m->>'integration_id') AND deleted_at IS NULL AND state<>'deleted' FOR SHARE;
 IF target_version IS NULL OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'targets') t WHERE(t->>'organization_id',t->>'workspace_id',t->>'environment_id',t->>'kind',COALESCE(NULLIF(t->>'source_id',''),t->>'id'),(t->>'version')::bigint)=(m->>'organization_id',m->>'workspace_id',m->>'environment_id','integration',m->>'integration_id',target_version)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='discovery human target changed';END IF;
 PERFORM zasp_authorization80.identity_fence(p);
 IF zasp_authorization80.context() IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery human proof expired';END IF;
END $check$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_replay() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $replay$
DECLARE m jsonb:=zasp_authorization80_worker.discovery72_human_marker();BEGIN
 IF m->>'stage' IS DISTINCT FROM 'entry' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery replay invocation rejected';END IF;
 PERFORM zasp_authorization80_worker.discovery72_human_check(m,0);
 PERFORM zasp_authorization80_worker.discovery72_human_clear();
END $replay$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_begin(op text,o text,w text,e text,actor text,i text,k text,a text,c text,receipt text,request jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $begin$
DECLARE p jsonb:=zasp_authorization80.context();m jsonb;delta bigint:=0;s record;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF op NOT IN('syncIntegration','putIntegrationSchedule','deleteIntegrationSchedule') OR p IS NULL OR NULLIF(current_setting('zasp.discovery72_human',true),'') IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery human entry rejected';END IF;
 m:=jsonb_build_object('domain','discovery72-human-v1','stage','entry','key_version',p->>'key_version','proof_digest',encode(digest(convert_to(p::text,'UTF8'),'sha256'),'hex'),'organization_id',o,'workspace_id',w,'environment_id',e,'actor',actor,'integration_id',i,'operation',op,'idempotency_key',k,'audit_id',a,'correlation_id',c,'receipt_id',receipt,'request',request);
 PERFORM zasp_authorization80_worker.discovery72_human_check(m,0);
 IF op='syncIntegration' THEN delta:=1;
 ELSE
  -- Prelock every affected capture under the held org revision. Already-false
  -- rows remain false and capture_revision does not touch for those updates.
  FOR s IN SELECT st.* FROM zasp_authorization80_worker.discovery_state st JOIN zasp_authorization80_worker.discovery_associations x USING(organization_id,workspace_id,environment_id,job_id)
   JOIN zasp_temporal72.schedules n ON(n.organization_id,n.workspace_id,n.environment_id,n.id)=(x.organization_id,x.workspace_id,x.environment_id,x.schedule_id)
   WHERE(n.organization_id,n.workspace_id,n.environment_id,n.integration_id)=(o,w,e,i) ORDER BY st.job_id FOR UPDATE OF st LOOP
   IF s.current_source THEN delta:=delta+1;END IF;
  END LOOP;
 END IF;
 PERFORM zasp_authorization80_worker.discovery72_human_check(m,0);
 PERFORM zasp_authorization80_worker.discovery72_human_save(m||jsonb_build_object('mutation_delta',delta));
END $begin$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_human_capture(v public.zasp_workflow_idempotency) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture$
DECLARE m jsonb:=zasp_authorization80_worker.discovery72_human_marker();BEGIN
 IF m->>'stage' IS DISTINCT FROM 'recording' OR(v.organization_id,v.workspace_id,v.environment_id,v.principal_id,v.operation,v.idempotency_key) IS DISTINCT FROM(m->>'organization_id',m->>'workspace_id',m->>'environment_id',m->>'actor',m->>'operation',m->>'idempotency_key')
 OR encode(v.request_digest,'hex') IS DISTINCT FROM m->>'intent_digest' OR encode(digest(convert_to(v.response::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM m->>'response_digest'
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery live capture invocation rejected';END IF;
 PERFORM zasp_authorization80_worker.discovery72_human_check(m,(m->>'mutation_delta')::bigint);
END $capture$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_record_public_mutation(o text,w text,e text,actor text,op text,k text,intent jsonb,body jsonb,kind text,id text,version_value bigint,a text,c text,receipt text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $record$
DECLARE m jsonb:=zasp_authorization80_worker.discovery72_human_marker();result jsonb;response jsonb;delta bigint;BEGIN
 IF m->>'stage' IS DISTINCT FROM 'entry' OR(o,w,e,actor,op,k,a,c,receipt) IS DISTINCT FROM(m->>'organization_id',m->>'workspace_id',m->>'environment_id',m->>'actor',m->>'operation',m->>'idempotency_key',m->>'audit_id',m->>'correlation_id',m->>'receipt_id')
 OR intent->'scope' IS DISTINCT FROM jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e)
 OR(intent->>'integration_id',intent->>'idempotency_key',intent->'expected_version') IS DISTINCT FROM(m->>'integration_id',k,m#>'{request,expected}')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery mutation invocation rejected';END IF;
 IF op='syncIntegration' THEN
  IF kind<>'integration_sync' OR id IS DISTINCT FROM m#>>'{request,sync_id}' OR body->>'id' IS DISTINCT FROM id OR intent->'body' IS DISTINCT FROM '{}'::jsonb
  OR NOT EXISTS(SELECT 1 FROM zasp_temporal72.runs r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.job_id,r.sync_id,r.integration_id,r.outbox_id,encode(r.request_digest,'hex'))=(o,w,e,m#>>'{request,job_id}',id,m->>'integration_id',m#>>'{request,outbox_id}',m#>>'{request,request_digest}')) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery manual invocation changed';END IF;
 ELSE
  IF kind<>'integration_schedule' OR id IS DISTINCT FROM m->>'integration_id' OR body->>'integration_id' IS DISTINCT FROM id OR version_value IS DISTINCT FROM(m#>>'{request,expected}')::bigint+1
  OR(op='putIntegrationSchedule' AND intent->'body' IS DISTINCT FROM jsonb_build_object('cadence_seconds',m#>'{request,cadence}','state',m#>'{request,state}')) OR(op='deleteIntegrationSchedule' AND intent->'body' IS DISTINCT FROM '{}'::jsonb)
  THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule invocation changed';END IF;
 END IF;
 delta:=(m->>'mutation_delta')::bigint;PERFORM zasp_authorization80_worker.discovery72_human_check(m,delta);
 response:=jsonb_build_object('body',body,'version',version_value,'audit_id',a,'correlation_id',c,'receipt_id',receipt);
 m:=m||jsonb_build_object('stage','recording','intent_digest',encode(digest(convert_to(intent::text,'UTF8'),'sha256'),'hex'),'response_digest',encode(digest(convert_to(response::text,'UTF8'),'sha256'),'hex'));
 PERFORM zasp_authorization80_worker.discovery72_human_save(m);
 result:=public.zasp_execution_record_public_mutation(o,w,e,actor,op,k,intent,body,kind,id,version_value,a,c,receipt);
 PERFORM zasp_authorization80_worker.discovery72_human_check(m,delta+CASE WHEN op='syncIntegration' THEN 1 ELSE 0 END);
 IF result-'replayed' IS DISTINCT FROM response OR result->'replayed' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery mutation receipt changed';END IF;
 PERFORM zasp_authorization80_worker.discovery72_human_clear();RETURN result;
END $record$;

-- Discovery roles are distinct from executor/adapter roles. Capture recovery
-- uses only the already registered compensation session and purpose.
CREATE FUNCTION zasp_authorization80_worker.discovery72_role(compensation boolean) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $role$
BEGIN
 IF compensation IS NULL OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='discovery worker isolation rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal72.current_ready() THEN RETURN false;END IF;
 RETURN CASE WHEN compensation THEN zasp_temporal68.principal_ready('zasp_temporal_compensation') ELSE EXISTS(SELECT 1 FROM zasp_temporal72.principals WHERE principal_name=session_user AND authority_role='zasp_discovery_worker') END;
END $role$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_key_ready(p text,v text) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $key$
 SELECT COALESCE(p IN('worker-forward','captured-compensation') AND zasp_authorization80_worker.discovery72_role(p='captured-compensation') AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.verifiers WHERE purpose=p AND version=v),false)
$key$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_revision(o text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $revision$
BEGIN
 IF NOT zasp_authorization80_worker.discovery72_role(false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery revision session rejected';END IF;
 RETURN(SELECT jsonb_build_object('organization_id',organization_id,'desired',desired,'applied',applied,'generation',generation,'store_id',store_id,'model_id',model_id) FROM zasp_authorization79.organizations WHERE organization_id=o);
END $revision$;

-- The native wrapper and typed adapter share this canonical request shape.
-- Time is integer microseconds so a session timezone cannot alter a proof.
CREATE FUNCTION zasp_authorization80_worker.discovery72_request(phase text,o text,w text,e text,j text,extra jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $request$
DECLARE a zasp_authorization80_worker.discovery_associations%ROWTYPE;BEGIN
 SELECT * INTO STRICT a FROM zasp_authorization80_worker.discovery_associations WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'job_id',j,'integration_id',a.integration_id,'input_digest',a.admission->>'request_digest','operation',phase)||extra;
END $request$;
CREATE FUNCTION zasp_authorization80_worker.discovery72_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE a zasp_authorization80_worker.discovery_associations%ROWTYPE;r zasp_temporal72.runs%ROWTYPE;s zasp_authorization80_worker.discovery_state%ROWTYPE;extra text[];page_value jsonb;apply_value jsonb;wait_value jsonb;compensation boolean:=phase IN('record_page','settle','finish','replay_page','replay_apply');checks jsonb:='[]'::jsonb;BEGIN
 IF phase IS NULL OR phase NOT IN('prepare_page','guard_page','prepare_apply','commit_apply','record_page','settle','finish','replay_page','replay_apply') OR NOT zasp_authorization80_worker.discovery72_role(compensation) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery worker phase/session rejected';END IF;
 extra:=CASE phase WHEN 'prepare_page' THEN ARRAY['budget_us','expected','expected_digest'] WHEN 'replay_page' THEN ARRAY['budget_us','expected','expected_digest'] WHEN 'guard_page' THEN ARRAY['effect_id','budget_us'] WHEN 'prepare_apply' THEN ARRAY['budget_us','complete_receipt'] WHEN 'replay_apply' THEN ARRAY['budget_us','complete_receipt'] WHEN 'commit_apply' THEN ARRAY['effect_id','budget_us'] WHEN 'record_page' THEN ARRAY['effect_id','details'] WHEN 'settle' THEN ARRAY['budget_us','reason','receipt'] WHEN 'finish' THEN ARRAY['outcome','receipt'] END;
 IF q->>'operation' IS DISTINCT FROM phase OR octet_length(q::text)>(CASE WHEN phase='record_page' THEN 67174400 ELSE 4096 END) OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','job_id','integration_id','input_digest','operation']||extra) OR EXISTS(SELECT 1 FROM jsonb_each(q) WHERE value='null'::jsonb) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery request rejected';END IF;
 SELECT * INTO a FROM zasp_authorization80_worker.discovery_associations WHERE(organization_id,workspace_id,environment_id,job_id,integration_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'job_id',q->>'integration_id');
 SELECT * INTO r FROM zasp_temporal72.runs WHERE(organization_id,workspace_id,environment_id,job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) FOR SHARE;
 SELECT * INTO s FROM zasp_authorization80_worker.discovery_state WHERE(organization_id,workspace_id,environment_id,job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) FOR SHARE;
 IF a.job_id IS NULL OR r.job_id IS NULL OR s.job_id IS NULL OR NOT s.present OR a.admission IS DISTINCT FROM zasp_authorization80_worker.discovery72_admission_identity(r) OR a.admission->>'request_digest' IS DISTINCT FROM q->>'input_digest' OR s.state IS DISTINCT FROM r.state OR a.deadline IS DISTINCT FROM r.deadline OR q ? 'budget_us' AND q->'budget_us' IS DISTINCT FROM to_jsonb(floor(extract(epoch FROM r.deadline)*1000000)::bigint) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery captured source rejected';END IF;
 IF NOT compensation THEN
  IF NOT s.current_source OR a.authority_until<=clock_timestamp() OR s.authority_until IS DISTINCT FROM a.authority_until OR a.credential_facts IS DISTINCT FROM zasp_authorization80_worker.discovery72_credentials(r) OR r.state NOT IN('admitted','collecting','partial','retryable','complete','applying') OR NOT EXISTS(SELECT 1 FROM public.zasp_identity_memberships WHERE(organization_id,principal_id,active)=(a.organization_id,a.grantor_id,true)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery delegation revoked';END IF;
  PERFORM zasp_temporal72.require_current_run(r,r.deadline);
  IF a.schedule_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_temporal72.schedules n JOIN zasp_authorization80_worker.discovery_schedule_grants g ON(g.organization_id,g.workspace_id,g.environment_id,g.schedule_id,g.version)=(n.organization_id,n.workspace_id,n.environment_id,n.id,n.version) WHERE(n.organization_id,n.workspace_id,n.environment_id,n.id,n.version,n.state)=(a.organization_id,a.workspace_id,a.environment_id,a.schedule_id,a.schedule_version,'enabled') AND g.identity=zasp_authorization80_worker.discovery72_schedule_identity(n) AND g.provenance=a.provenance) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery schedule delegation changed';END IF;
  checks:=jsonb_build_array(jsonb_build_object('kind','integration','id',a.integration_id,'permission','manage_workflows'),jsonb_build_object('kind','integration','id',a.integration_id,'permission','view'));
 END IF;
 IF phase IN('prepare_page','replay_page') AND(q->>'expected' !~ '^[0-9]+$' OR(q->>'expected')::bigint NOT BETWEEN 0 AND 9999 OR jsonb_typeof(q->'expected_digest') IS DISTINCT FROM 'string') THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='discovery checkpoint shape rejected';END IF;
 SELECT jsonb_build_object('effect_id',p.effect_id,'expected',p.expected_version,'expected_digest',p.expected_digest,'record_digest',p.record_digest,'result',p.result) INTO page_value FROM zasp_temporal72.page_effects p WHERE(p.organization_id,p.workspace_id,p.environment_id,p.job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) AND(CASE WHEN phase IN('prepare_page','replay_page') THEN p.expected_version=(q->>'expected')::bigint ELSE p.effect_id=q->>'effect_id' END) FOR SHARE;
 SELECT jsonb_build_object('effect_id',v.effect_id,'complete_digest',v.complete_digest,'result',v.result) INTO apply_value FROM zasp_temporal72.apply_effects v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.job_id)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id) FOR SHARE;
 IF phase IN('prepare_page','replay_page') THEN SELECT jsonb_build_object('expected',v.expected_version,'expected_digest',v.expected_digest,'result',v.result) INTO wait_value FROM zasp_temporal72.page_waits v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.job_id,v.expected_version)=(a.organization_id,a.workspace_id,a.environment_id,a.job_id,(q->>'expected')::bigint) FOR SHARE;END IF;
 IF phase IN('guard_page','record_page') AND page_value IS NULL OR phase='commit_apply' AND(apply_value IS NULL OR apply_value->>'effect_id' IS DISTINCT FROM q->>'effect_id') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery prepared effect absent';END IF;
 -- Native entries are independently callable, so their single fence must
 -- refresh authority after every source lock, not rely on the dispatcher.
 IF NOT compensation AND a.authority_until<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery authority expired after source locks';END IF;
 RETURN jsonb_build_object('organization_id',a.organization_id,'workspace_id',a.workspace_id,'environment_id',a.environment_id,'run_id',a.job_id,'task_id',a.sync_id,'principal_id',a.principal_id,'grantor_id',a.grantor_id,'trigger_kind',a.source_kind,'target_kind','integration','target_id',a.integration_id,'session_user',session_user,'checks',checks,'admission',a.admission,'provenance',a.provenance,'state',r.state,'checkpoint_version',r.checkpoint_version,'checkpoint_digest',r.checkpoint_digest,'page',page_value,'apply',apply_value,'wait',wait_value,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'));
END $source$;
CREATE FUNCTION zasp_authorization80_worker.prepare_discovery72(q jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $prepare$
BEGIN
 -- Capture belongs to the API/admission transaction, never a worker-selected
 -- grantor. This verifies the existing exact capture without issuing input.
 PERFORM zasp_authorization80_worker.discovery72_source(q->>'operation',q);
 IF q->>'operation' NOT IN('prepare_page','prepare_apply') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery preparation phase rejected';END IF;
END $prepare$;

DO $proof$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning78(text,jsonb)'::regprocedure) INTO d;
 d:=replace(replace(replace(d,'require_planning78','require_discovery72'),'planning78_source','discovery72_source'),'finding.planning.','discovery72.');
 needle:=$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery proof phases changed';END IF;
 d:=replace(d,needle,$new$('prepare_page','guard_page','prepare_apply','commit_apply','record_page','settle','finish','replay_page','replay_apply')$new$);
 needle:=$old$('reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery proof purpose changed';END IF;
 d:=replace(d,needle,$new$('record_page','settle','finish','replay_page','replay_apply')$new$);
 needle:=$old$zasp_temporal68.principal_ready(CASE purpose_value WHEN 'worker-forward' THEN 'zasp_temporal_executor' ELSE 'zasp_temporal_compensation' END)$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery proof principal changed';END IF;
 d:=replace(d,needle,$new$zasp_authorization80_worker.discovery72_role(purpose_value='captured-compensation')$new$);
 -- The shared fence now gives forward and captured calls the same org-first
 -- lock order, then materializes source and rechecks time before equality.
 needle:=$old$ SELECT * INTO revision_value FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 OR strpos(d,needle)>strpos(d,$old$ IF purpose_value='worker-forward' THEN$old$) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery proof organization lock changed';END IF;
 needle:=$old$ source_value:=zasp_authorization80_worker.discovery72_source(phase,q);
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT COALESCE((proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker proof expired after source locks';END IF;
 IF proof->'facts' IS DISTINCT FROM source_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker planning source changed';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='discovery proof final source fence changed';END IF;
 EXECUTE d;
END $proof$;

CREATE FUNCTION zasp_authorization80_worker.discovery72_execute(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $execute$
DECLARE phase text:=q->>'operation';o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';j text:=q->>'job_id';i text:=q->>'integration_id';d text:=q->>'input_digest';budget timestamptz:=CASE WHEN q ? 'budget_us' THEN timestamptz 'epoch'+(q->>'budget_us')::bigint*interval '1 microsecond' END;p zasp_temporal72.page_effects%ROWTYPE;v zasp_temporal72.page_waits%ROWTYPE;a zasp_temporal72.apply_effects%ROWTYPE;BEGIN
 PERFORM zasp_authorization80_worker.require_discovery72(phase,q);
 CASE phase
 WHEN 'prepare_page' THEN RETURN zasp_temporal72.prepare_page(o,w,e,j,i,d,budget,(q->>'expected')::bigint,q->>'expected_digest');
 WHEN 'guard_page' THEN RETURN to_jsonb(zasp_temporal72.guard_page_effect(o,w,e,j,q->>'effect_id',budget));
 WHEN 'prepare_apply' THEN RETURN zasp_temporal72.prepare_apply(o,w,e,j,i,d,budget,q->>'complete_receipt');
 WHEN 'commit_apply' THEN RETURN zasp_temporal72.commit_apply(o,w,e,j,q->>'effect_id',budget);
 WHEN 'record_page' THEN RETURN zasp_authorization80_worker.discovery72_record_page(o,w,e,j,q->>'effect_id',q->'details');
 WHEN 'settle' THEN RETURN zasp_authorization80_worker.discovery72_settle(o,w,e,j,i,d,budget,q->>'reason',q->>'receipt');
 WHEN 'finish' THEN RETURN zasp_authorization80_worker.discovery72_finish(o,w,e,j,i,d,q->>'outcome',q->>'receipt');
 WHEN 'replay_page' THEN
  SELECT * INTO v FROM zasp_temporal72.page_waits WHERE(organization_id,workspace_id,environment_id,job_id,expected_version)=(o,w,e,j,(q->>'expected')::bigint);
  IF FOUND THEN IF v.expected_digest IS DISTINCT FROM q->>'expected_digest' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery wait replay conflict';END IF;RETURN jsonb_build_object('found',true,'value',jsonb_build_object('page',v.result));END IF;
  SELECT * INTO p FROM zasp_temporal72.page_effects WHERE(organization_id,workspace_id,environment_id,job_id,expected_version)=(o,w,e,j,(q->>'expected')::bigint);
  IF FOUND THEN IF p.expected_digest IS DISTINCT FROM q->>'expected_digest' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery page replay conflict';END IF;RETURN jsonb_build_object('found',true,'value',jsonb_build_object('page',COALESCE(p.result,jsonb_build_object('outcome','outcome_unknown'))));END IF;
 WHEN 'replay_apply' THEN
  SELECT * INTO a FROM zasp_temporal72.apply_effects WHERE(organization_id,workspace_id,environment_id,job_id)=(o,w,e,j);
  IF FOUND THEN IF a.complete_digest IS DISTINCT FROM q->>'complete_receipt' THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='discovery apply replay conflict';END IF;RETURN jsonb_build_object('found',true,'value',jsonb_build_object('result',COALESCE(a.result,jsonb_build_object('outcome','outcome_unknown'))));END IF;
 ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='discovery phase closed';
 END CASE;
 RETURN jsonb_build_object('found',false);
END $execute$;
