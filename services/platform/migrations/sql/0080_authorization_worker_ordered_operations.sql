-- Ordinary native operations are distinct from signing. A nested
-- effect read does not turn forward application completion into compensation.
CREATE FUNCTION zasp_authorization80_worker.ordered68_operation_source(operation_value text,q jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $source$
DECLARE compensation boolean;delivery_value boolean;phase_value text;f jsonb;effect_q jsonb;evidence jsonb;
 t public.zasp_security_agent_temporary_policy_targets%ROWTYPE;v zasp_temporal68.deliveries%ROWTYPE;
 c zasp_temporal68.cleanups%ROWTYPE;BEGIN
 IF operation_value IS NULL OR operation_value NOT IN('ordered68.application.read','ordered68.application.complete',
 'ordered68.cleanup.prepare','ordered68.cleanup.read','ordered68.cleanup.complete',
 'ordered68.delivery.apply.prepare','ordered68.delivery.apply.read','ordered68.delivery.apply.ack',
 'ordered68.delivery.cleanup.prepare','ordered68.delivery.cleanup.read','ordered68.delivery.cleanup.ack')
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered ordinary operation rejected';END IF;
 compensation:=operation_value NOT IN('ordered68.application.read','ordered68.application.complete','ordered68.delivery.apply.prepare');
 delivery_value:=starts_with(operation_value,'ordered68.delivery.');
 phase_value:=CASE WHEN starts_with(operation_value,'ordered68.delivery.cleanup.') THEN 'cleanup' ELSE 'apply' END;
 IF NOT COALESCE(octet_length(q::text)<=32768 AND q->'generation'='1'::jsonb
 AND q->>'operation'=split_part(operation_value,'.',CASE WHEN delivery_value THEN 4 ELSE 3 END),false)
 OR NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','step_id','generation','operation','payload'])
 OR NOT delivery_value AND q->'payload' IS DISTINCT FROM '{}'::jsonb
 OR delivery_value AND(NOT COALESCE(public.zasp_valid_product_id(q#>>'{payload,device_id}') AND q#>>'{payload,phase}'=phase_value,false)
  OR NOT zasp_sa_multistep_prior.closed(q->'payload',CASE WHEN q->>'operation'='prepare' THEN ARRAY['device_id','phase'] ELSE ARRAY['device_id','phase','digest'] END)
  OR q->>'operation'<>'prepare' AND NOT COALESCE(q#>>'{payload,digest}'~'^sha256:[a-f0-9]{64}$',false))
 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered ordinary request rejected';END IF;
 IF operation_value='ordered68.delivery.apply.prepare' THEN
  -- Complete native composition capture precedes the creation of a delivery.
  RETURN zasp_authorization80_worker.ordered68_policy_source(operation_value,q);
 END IF;
 effect_q:=q||jsonb_build_object('operation',CASE WHEN compensation THEN 'read' ELSE 'start' END,'payload','{}'::jsonb);
 f:=zasp_authorization80_worker.ordered68_effect_source(CASE WHEN compensation THEN 'effect.read' ELSE 'effect.start' END,effect_q);
 IF f->>'ordered_action_key' IS DISTINCT FROM 'create_temporary_policy' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered ordinary Block intent rejected';END IF;
 IF NOT compensation THEN
  -- First completion and receipt replay both retain all current native gates.
  PERFORM zasp_sa_multistep_prior.application_current(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
 END IF;
 IF delivery_value THEN
  SELECT * INTO t FROM public.zasp_security_agent_temporary_policy_targets
  WHERE(organization_id,workspace_id,environment_id,run_id,step_id,phase,device_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',phase_value,q#>>'{payload,device_id}') FOR UPDATE;
  IF t.device_id IS NULL OR t.state NOT IN('stored','verified') OR t.envelope_digest IS NULL OR t.desired_generation IS NULL
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured delivery target absent';END IF;
  SELECT * INTO v FROM zasp_temporal68.deliveries
  WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation,phase,device_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id,1,phase_value,t.device_id) FOR UPDATE;
  IF v.run_id IS NULL AND operation_value<>'ordered68.delivery.cleanup.prepare'
   OR v.run_id IS NOT NULL AND(v.source_sequence,v.source_digest,v.credential_id) IS DISTINCT FROM(t.sequence,t.envelope_digest,t.credential_id)
   OR q->>'operation'<>'prepare' AND(v.state NOT IN('stored','read','acknowledged') OR q#>>'{payload,digest}' IS DISTINCT FROM 'sha256:'||encode(v.envelope_digest,'hex'))
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured delivery association changed';END IF;
  IF phase_value='cleanup' THEN
   PERFORM zasp_temporal68.cleanup_current(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.step_id);
  END IF;
  evidence:=jsonb_build_array(zasp_authorization80_worker.ordered68_row_json(t),zasp_authorization80_worker.ordered68_row_json(v));
 ELSIF starts_with(operation_value,'ordered68.cleanup.') THEN
  SELECT * INTO c FROM zasp_temporal68.cleanups WHERE(organization_id,workspace_id,environment_id,run_id,step_id,generation)
   =(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',1) FOR UPDATE;
  IF c.run_id IS NULL THEN
   IF operation_value<>'ordered68.cleanup.prepare' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered captured cleanup absent';END IF;
   evidence:=zasp_temporal68.cleanup_snapshot(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id');
  ELSE
   PERFORM zasp_temporal68.cleanup_current(c.organization_id,c.workspace_id,c.environment_id,c.run_id,c.step_id);
   evidence:=zasp_authorization80_worker.ordered68_row_json(c);
  END IF;
 ELSE
  -- Bind the actual acknowledged delivery/source/receipt association, including
  -- receipt absence on the first completion. No audit or receipt is fabricated.
  SELECT jsonb_build_array(
   (SELECT COALESCE(jsonb_agg(zasp_authorization80_worker.ordered68_row_json(target_evidence) ORDER BY target_evidence.device_id),'[]'::jsonb) FROM public.zasp_security_agent_temporary_policy_targets target_evidence WHERE(target_evidence.organization_id,target_evidence.workspace_id,target_evidence.environment_id,target_evidence.run_id,target_evidence.step_id,target_evidence.phase)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id','apply')),
   (SELECT COALESCE(jsonb_agg(zasp_authorization80_worker.ordered68_row_json(d) ORDER BY device_id),'[]'::jsonb) FROM zasp_temporal68.deliveries d WHERE(d.organization_id,d.workspace_id,d.environment_id,d.run_id,d.step_id,d.generation,d.phase)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id',1,'apply')),
   (SELECT zasp_authorization80_worker.ordered68_row_json(r) FROM public.zasp_sa_multistep_receipts r WHERE(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.step_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'run_id',q->>'step_id'))) INTO evidence;
 END IF;
 IF evidence IS NULL OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()
 OR NOT zasp_temporal68.principal_ready(CASE WHEN compensation THEN 'zasp_temporal_compensation' ELSE 'zasp_temporal_executor' END)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered ordinary session changed after wait';END IF;
 RETURN f||jsonb_build_object('execution_phase',operation_value,'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),
 'operation_evidence_digest',encode(digest(convert_to(evidence::text,'UTF8'),'sha256'),'hex'));
END $source$;

DO $ordinary_proof$ DECLARE d text;BEGIN
 SELECT pg_get_functiondef('zasp_authorization80_worker.require_planning68(text,jsonb)'::regprocedure) INTO d;
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
 d:=replace(replace(d,'require_planning68','require_ordered68_operation'),'planning68_source','ordered68_operation_source');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$,$new$('ordered68.application.read','ordered68.application.complete','ordered68.cleanup.prepare','ordered68.cleanup.read','ordered68.cleanup.complete','ordered68.delivery.apply.prepare','ordered68.delivery.apply.read','ordered68.delivery.apply.ack','ordered68.delivery.cleanup.prepare','ordered68.delivery.cleanup.read','ordered68.delivery.cleanup.ack')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('reconcile','late_usage','recovery')$old$,$new$('ordered68.cleanup.prepare','ordered68.cleanup.read','ordered68.cleanup.complete','ordered68.delivery.apply.read','ordered68.delivery.apply.ack','ordered68.delivery.cleanup.prepare','ordered68.delivery.cleanup.read','ordered68.delivery.cleanup.ack')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$proof->>'operation'='ordered68.planning.'||phase$old$,$new$proof->>'operation'=phase$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,E' RETURNS void\n',E' RETURNS jsonb\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,'EXCEPTION WHEN data_exception THEN',E' RETURN proof;\nEXCEPTION WHEN data_exception THEN');
 EXECUTE d;
END $ordinary_proof$;

CREATE FUNCTION zasp_authorization80_worker.ordered68_operation_session(proof jsonb) RETURNS void
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $session$
BEGIN
 PERFORM zasp_authorization80_worker.ordered68_policy_proof_time(proof);
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal68.current_ready()
 OR proof->>'session_user' IS DISTINCT FROM session_user
 OR NOT zasp_temporal68.principal_ready(CASE proof->>'purpose' WHEN 'worker-forward' THEN 'zasp_temporal_executor' WHEN 'captured-compensation' THEN 'zasp_temporal_compensation' END)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered ordinary session changed';END IF;
END $session$;

-- Replace only saved exact public entries. Signing source/store operations are
-- refused here; the purpose-bound begin/store protocol uses private copies.
DO $ordinary_boundaries$ DECLARE p record;d text;phase text;needle text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions
 WHERE signature IN('zasp_temporal68.application(jsonb)','zasp_temporal68.cleanup(jsonb)','zasp_temporal68.delivery(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR p.acl IS DISTINCT FROM (CASE WHEN p.signature='zasp_temporal68.application(jsonb)' THEN '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}' ELSE '{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' END)
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered ordinary predecessor changed';END IF;
  IF p.signature='zasp_temporal68.application(jsonb)' THEN
   phase:=$phase$'ordered68.application.'||(q->>'operation')$phase$;
   needle:=$last$ IF op='complete' THEN RETURN jsonb_build_object('effect_key',intent->>'effect_key','receipt_kind',receipt.receipt_kind,'receipt',receipt.body,'result_digest','sha256:'||encode(receipt.result_digest,'hex'));END IF;$last$;
  ELSIF p.signature='zasp_temporal68.cleanup(jsonb)' THEN
   phase:=$phase$'ordered68.cleanup.'||(q->>'operation')$phase$;
   needle:=$last$ IF op IN('read','source','renew') THEN$last$;
  ELSE
   phase:=$phase$'ordered68.delivery.'||(q#>>'{payload,phase}')||'.'||(q->>'operation')$phase$;
   needle:=$last$ RETURN response_value;$last$;
  END IF;
  d:=zasp_authorization80_worker.ordered62_replace(p.definition,'DECLARE o text;','DECLARE worker_proof jsonb;o text;');
  d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n worker_proof:=zasp_authorization80_worker.require_ordered68_operation('||phase||E',q);\n');
  d:=zasp_authorization80_worker.ordered62_replace(d,$read$zasp_temporal68.effect(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$read$,$read$zasp_authorization80_worker.ordered68_effect_read(q||jsonb_build_object('operation','read','payload','{}'::jsonb))$read$);
  d:=zasp_authorization80_worker.ordered62_replace(d,needle,E' PERFORM zasp_authorization80_worker.ordered68_operation_session(worker_proof);\n'||needle);
  EXECUTE d;
 END LOOP;
END $ordinary_boundaries$;
