CREATE FUNCTION public.zasp_sa_export_selection(selection jsonb) RETURNS void LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $selection$
DECLARE x jsonb;
BEGIN
 IF jsonb_typeof(selection) IS DISTINCT FROM 'array' OR jsonb_array_length(selection) NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export selection rejected';END IF;
 FOR x IN SELECT value FROM jsonb_array_elements(selection) LOOP
  IF jsonb_typeof(x) IS DISTINCT FROM 'object' OR NOT x ?& ARRAY['source_kind','source_id','source_version','association_digest'] OR x-ARRAY['source_kind','source_id','source_version','association_digest']<>'{}'
  OR jsonb_typeof(x->'source_kind') IS DISTINCT FROM 'string' OR x->>'source_kind' NOT IN('finding','attack_path','runtime_decision','run_audit','manual','existing_test','attack_lab')
  OR jsonb_typeof(x->'source_id') IS DISTINCT FROM 'string' OR NOT COALESCE(CASE WHEN x->>'source_kind'='manual' THEN x->>'source_id' ~ '^[a-f0-9]{64}$' ELSE public.zasp_valid_product_id(x->>'source_id') END,false)
  OR jsonb_typeof(x->'source_version') IS DISTINCT FROM 'number' OR NOT COALESCE(x->>'source_version' ~ '^[1-9][0-9]{0,15}$',false) OR (x->>'source_version')::numeric>9007199254740991
  OR jsonb_typeof(x->'association_digest') IS DISTINCT FROM 'string' OR NOT COALESCE(x->>'association_digest' ~ '^sha256:[a-f0-9]{64}$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export reference rejected';END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(selection) selected(value) GROUP BY selected.value->>'source_kind',selected.value->>'source_id' HAVING count(*)>1) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='export duplicate reference';END IF;
END $selection$;

CREATE FUNCTION public.zasp_sa_export_collect(o text,w text,e text,r text,s text,selection jsonb,stamp timestamptz) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $collect$
DECLARE x jsonb;body jsonb;records jsonb:='[]';association bytea;content text;result_value jsonb;receipt public.zasp_security_agent_trigger_receipts%ROWTYPE;path public.zasp_risk_attack_paths%ROWTYPE;proof_step public.zasp_security_agent_steps%ROWTYPE;effect public.zasp_security_agent_effects%ROWTYPE;arguments jsonb;step_value jsonb;
BEGIN
 PERFORM public.zasp_sa_export_selection(selection);
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_runs rr JOIN public.zasp_security_agent_steps st USING(organization_id,workspace_id,environment_id,run_id) WHERE (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,st.step_id,st.action_key)=(o,w,e,r,s,'create_evidence_export') AND rr.state<>'simulated') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='export source scope rejected';END IF;
 -- STABLE SPI statements retain the outer statement's snapshot for the whole
 -- selection. Version changes never cause collection of a newer source.
 FOR x IN SELECT value FROM jsonb_array_elements(selection) LOOP
  body:=NULL;association:=NULL;
  IF x->>'source_kind' NOT IN('run_audit','existing_test','attack_lab') THEN
   SELECT t.* INTO receipt FROM public.zasp_security_agent_trigger_receipts t JOIN public.zasp_security_agent_runs rr ON (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.definition_id,rr.trigger_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id)
   WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.trigger_kind,t.trigger_id,t.trigger_version)=(o,w,e,r,x->>'source_kind',x->>'source_id',(x->>'source_version')::bigint);
   IF NOT FOUND OR 'sha256:'||encode(receipt.trigger_digest,'hex') IS DISTINCT FROM x->>'association_digest' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export receipt association rejected';END IF;
  END IF;
  IF x->>'source_kind'='finding' THEN
  SELECT t.trigger_digest INTO association FROM public.zasp_security_agent_trigger_receipts t
  JOIN public.zasp_security_agent_runs rr ON (rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.definition_id,rr.trigger_id)=(t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id)
  JOIN public.zasp_risk_findings f ON (f.organization_id,f.workspace_id,f.environment_id,f.id,f.version)=(t.organization_id,t.workspace_id,t.environment_id,t.trigger_id,t.trigger_version)
  WHERE (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.trigger_kind,t.trigger_id,t.trigger_version)=(o,w,e,r,'finding',x->>'source_id',(x->>'source_version')::bigint);
  IF NOT FOUND OR association IS DISTINCT FROM digest(convert_to(jsonb_build_object('kind','finding','id',x->>'source_id','version',(x->>'source_version')::bigint)::text,'UTF8'),'sha256') OR 'sha256:'||encode(association,'hex') IS DISTINCT FROM x->>'association_digest' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export exact historical source unavailable';END IF;
   body:=public.zasp_risk_finding_get(x->>'source_id',o,w,e);
  ELSIF x->>'source_kind'='attack_path' THEN
   SELECT * INTO path FROM public.zasp_risk_attack_paths p WHERE (p.organization_id,p.workspace_id,p.environment_id,p.id,p.version)=(o,w,e,receipt.trigger_id,receipt.trigger_version) AND public.zasp_risk_attack_path_valid(p);
   IF NOT FOUND OR receipt.trigger_digest IS DISTINCT FROM digest(convert_to(jsonb_build_object('kind','attack_path','id',path.id,'version',path.version,'state',path.state)::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export exact historical path unavailable';END IF;
   body:=public.zasp_risk_attack_path_get(path.id,o,w,e);
  ELSIF x->>'source_kind'='runtime_decision' THEN
   -- Retained event identity, never newest event, credential freshness or a
   -- five-minute admission window. Classification is not copied wholesale.
   SELECT jsonb_build_object('session_id',receipt.trigger_id,'event_id',event.event_id,'device_id',event.device_id,'sequence',event.sequence,'decision',event.decision,'outcome',event.classification->>'outcome','policy_version',event.policy_version,'occurred_at',event.occurred_at,'request_digest','sha256:'||encode(event.request_digest,'hex')) INTO body
   FROM public.zasp_runtime_gateway_events event WHERE (event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.sequence)=(o,w,e,receipt.trigger_id,receipt.trigger_version)
   AND receipt.trigger_digest=digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',receipt.trigger_id,'device_id',event.device_id,'event_id',event.event_id,'sequence',event.sequence,'request_digest','sha256:'||encode(event.request_digest,'hex'))::text,'UTF8'),'sha256');
  ELSIF x->>'source_kind'='run_audit' THEN
   SELECT jsonb_build_object('id',a.audit_id,'run_id',a.run_id,'organization_id',a.organization_id,'workspace_id',a.workspace_id,'environment_id',a.environment_id,'actor_reference',a.actor_id,'event_kind',a.event_kind,'correlation_id',a.correlation_id,'occurred_at',to_char(a.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) INTO body
   FROM public.zasp_security_agent_audit a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.audit_id)=(o,w,e,r,x->>'source_id') AND (x->>'source_version')::bigint=1 AND 'sha256:'||encode(a.event_digest,'hex')=x->>'association_digest';
  ELSIF x->>'source_kind'='manual' THEN
   IF receipt.trigger_id IS DISTINCT FROM encode(receipt.trigger_digest,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export manual intent rejected';END IF;
   body:=jsonb_build_object('run_id',r,'definition_id',receipt.definition_id,'trigger_id',receipt.trigger_id,'trigger_kind',receipt.trigger_kind,'trigger_version',receipt.trigger_version,'trigger_digest','sha256:'||encode(receipt.trigger_digest,'hex'),'received_at',receipt.received_at);
  ELSIF x->>'source_kind' IN('existing_test','attack_lab') THEN
   SELECT st.* INTO proof_step FROM public.zasp_security_agent_steps st WHERE (st.organization_id,st.workspace_id,st.environment_id,st.run_id,st.step_id,st.version)=(o,w,e,r,x->>'source_id',(x->>'source_version')::bigint)
   AND (x->>'source_kind'='existing_test' AND st.action_key IN('run_test','rerun_test') OR x->>'source_kind'='attack_lab' AND st.action_key='start_attack_lab');
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export proof step unavailable';END IF;
   SELECT f.* INTO effect FROM public.zasp_security_agent_effects f WHERE (f.organization_id,f.workspace_id,f.environment_id,f.run_id,f.step_id,f.action_key,f.input_digest)=(o,w,e,r,proof_step.step_id,proof_step.action_key,proof_step.input_digest) AND f.result_digest IS NOT NULL AND 'sha256:'||encode(f.result_digest,'hex')=x->>'association_digest';
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export proof association unavailable';END IF;
   IF x->>'source_kind'='existing_test' THEN
    SELECT jsonb_build_object('target_id',l.test_definition_id,'expected_version',l.test_definition_version) INTO arguments FROM public.zasp_security_agent_test_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.action_key,l.input_digest)=(o,w,e,r,proof_step.step_id,proof_step.action_key,proof_step.input_digest);
   ELSE
    SELECT jsonb_build_object('target_id',l.source_snapshot->'definition_id','expected_version',l.source_snapshot->'definition_version') INTO arguments FROM public.zasp_sa_attack_lab_links l WHERE (l.organization_id,l.workspace_id,l.environment_id,l.run_id,l.step_id,l.action_key,l.input_digest)=(o,w,e,r,proof_step.step_id,proof_step.action_key,proof_step.input_digest);
   END IF;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export proof link unavailable';END IF;
   step_value:=jsonb_build_object('step_id',proof_step.step_id,'index',proof_step.step_index,'action',proof_step.action_key,'state',proof_step.state,'authorization',proof_step.authorization_result,'arguments',arguments,'effect',jsonb_build_object('step_id',effect.step_id,'action',effect.action_key,'state',effect.state,'outcome_id',effect.outcome_id,'result_digest','sha256:'||encode(effect.result_digest,'hex')));
   body:=CASE WHEN x->>'source_kind'='existing_test' THEN public.zasp_production_security_agent_existing_tests_public_step(o,w,e,r,step_value) ELSE public.zasp_sa_attack_lab_public_step(o,w,e,r,step_value) END;
  END IF;
  IF body IS NULL THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='export exact historical source unavailable';END IF;
  content:=body::text;
  IF octet_length(content)>65536 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='export source overflow';END IF;
  records:=records||jsonb_build_array(x||jsonb_build_object('content_json',content,'content_sha256',encode(digest(convert_to(content,'UTF8'),'sha256'),'hex')));
 END LOOP;
 result_value:=jsonb_build_object('mapping_revision','security-agent-run-evidence-v1','snapshot_at',regexp_replace(to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'\.?0+Z$','Z'),'organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'step_id',s,'records',records);
 IF octet_length(result_value::text)>4194304 THEN RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='export snapshot overflow';END IF;
 RETURN result_value;
END $collect$;
