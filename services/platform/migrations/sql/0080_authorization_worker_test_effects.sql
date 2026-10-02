-- Each execution phase binds canonical request bytes and the captured native
-- plan/step/effect/input identities. Bodies never enter the metadata response.
CREATE FUNCTION zasp_authorization80_worker.test74_effect_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $effect_source$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;a zasp_authorization80_worker.test_associations%ROWTYPE;f jsonb;reference_value jsonb;effect_value jsonb;input_value jsonb;step_value jsonb;
 compensation boolean:=phase IN('effect.read','effect.unknown','state');
BEGIN
 IF phase IS NULL OR phase NOT IN('effect.reserve','effect.start','effect.read','effect.unknown','linked.read','linked.input','linked.dispatch','state')
 OR octet_length(q::text)>131072 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload'])
 OR q->'generation' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(q->'payload') IS DISTINCT FROM 'object'
 OR q->>'operation' IS DISTINCT FROM (CASE WHEN phase='state' THEN 'read' ELSE split_part(phase,'.',2) END) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='worker test execution request rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 SELECT * INTO x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id,step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 IF x.run_id IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test execution owner rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));
 reference_value:=jsonb_build_object('organization_id',x.organization_id,'workspace_id',x.workspace_id,'environment_id',x.environment_id,'run_id',x.run_id,'definition_version',x.definition_version,'input_digest',x.input_digest);
 f:=zasp_authorization80_worker.test74_native_facts(compensation,reference_value,true);
 a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_associations s WHERE s=a) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test execution association rejected';END IF;
 IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_worker.test_state s WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.definition_id,s.definition_version,s.state,s.run_version,s.present)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.definition_id,a.definition_version,f->>'run_state',(f->>'run_version')::bigint,true) AND(compensation OR s.target_current AND s.fresh_until>clock_timestamp())) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='worker test execution capture changed';END IF;
 SELECT jsonb_build_object('action_key',s.action_key,'input_digest',encode(s.input_digest,'hex'),'state',s.state,'version',s.version,'plan_hash',encode(p.plan_hash,'hex')) INTO step_value FROM public.zasp_security_agent_steps s JOIN public.zasp_security_agent_plans p USING(organization_id,workspace_id,environment_id,run_id) WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id) FOR SHARE OF s,p;
 SELECT jsonb_build_object('effect_key',v.effect_key,'generation',v.generation,'snapshot_digest',encode(v.snapshot_digest,'hex'),'input_digest',encode(v.input_digest,'hex'),'plan_hash',encode(v.plan_hash,'hex'),'state',v.state) INTO effect_value FROM zasp_temporal74.effects v WHERE(v.organization_id,v.workspace_id,v.environment_id,v.run_id,v.step_id,v.generation)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id,1) FOR SHARE;
 SELECT jsonb_build_object('manifest_digest',encode(digest(convert_to(i.manifest::text,'UTF8'),'sha256'),'hex'),'body_digest',encode(digest(i.body,'sha256'),'hex')) INTO input_value FROM zasp_temporal74.test_inputs i WHERE(i.organization_id,i.workspace_id,i.environment_id,i.run_id,i.step_id)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,x.step_id) FOR SHARE;
 IF step_value IS NULL OR phase NOT IN('effect.reserve','state') AND effect_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker captured test effect absent';END IF;
 RETURN f||jsonb_build_object('execution_phase',phase,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'step',step_value,'effect',effect_value,'input',input_value,'child_run_id',x.test_run_id);
END $effect_source$;

-- This copies our own proof parser, not a historical authorization policy.
DO $effect_proof$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning74(text,jsonb)'::regprocedure) INTO d;
 d:=replace(replace(replace(d,'require_planning74','require_test74_effect'),'planning74_source','test74_effect_source'),'test74.planning.','test74.');
 needle:=$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker execution proof phases changed';END IF;
 d:=replace(d,needle,$new$('effect.reserve','effect.start','effect.read','effect.unknown','linked.read','linked.input','linked.dispatch','state')$new$);
 needle:=$old$('reconcile','late_usage','recovery')$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker execution proof purpose changed';END IF;
 EXECUTE replace(d,needle,$new$('effect.read','effect.unknown','state')$new$);
END $effect_proof$;

DO $effect_boundaries$ DECLARE d text;p record;needle text:=E'BEGIN\n';replacement text;call_value text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.effect(jsonb)';
 EXECUTE replace(d,'FUNCTION zasp_temporal74.effect(q jsonb)','FUNCTION zasp_authorization80_worker.test74_effect(q jsonb)');
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal74.effect(jsonb)','zasp_temporal74.linked(jsonb)','zasp_temporal74.test_state(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR(length(p.definition)-length(replace(p.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 execution predecessor rejected';END IF;
  replacement:=CASE p.signature WHEN 'zasp_temporal74.effect(jsonb)' THEN '''effect.''||(q->>''operation'')' WHEN 'zasp_temporal74.linked(jsonb)' THEN '''linked.''||(q->>''operation'')' ELSE '''state''' END;
  d:=replace(p.definition,needle,needle||' PERFORM zasp_authorization80_worker.require_test74_effect('||replacement||',q);'||E'\n');
  IF p.signature='zasp_temporal74.effect(jsonb)' THEN
   call_value:=$old$ RETURN to_jsonb(f)||jsonb_build_object('send_permit',permit);$old$;
   IF(length(d)-length(replace(d,call_value,'')))/length(call_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 effect receipt predecessor rejected';END IF;
   d:=replace(d,call_value,$new$ IF NOT live_value THEN RETURN jsonb_build_object('run_id',f.run_id,'step_id',f.step_id,'effect_key',f.effect_key,'generation',f.generation,'state',f.state,'send_permit',false);END IF;
 RETURN to_jsonb(f)||jsonb_build_object('send_permit',permit);$new$);
  ELSIF p.signature='zasp_temporal74.linked(jsonb)' THEN
   FOREACH call_value IN ARRAY ARRAY[$read$zasp_temporal74.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$read$,$start$zasp_temporal74.effect(q||jsonb_build_object('operation','start','payload','{}'::jsonb))$start$] LOOP
    IF(length(d)-length(replace(d,call_value,'')))/length(call_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 linked nested predecessor rejected';END IF;
    d:=replace(d,call_value,replace(call_value,'zasp_temporal74.effect','zasp_authorization80_worker.test74_effect'));
   END LOOP;
  ELSE
   call_value:='zasp_temporal74.effect(q)';
   IF(length(d)-length(replace(d,call_value,'')))/length(call_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='worker74 state nested predecessor rejected';END IF;
   d:=replace(d,call_value,'zasp_authorization80_worker.test74_effect(q)');
  END IF;
  EXECUTE d;
 END LOOP;
END $effect_boundaries$;
