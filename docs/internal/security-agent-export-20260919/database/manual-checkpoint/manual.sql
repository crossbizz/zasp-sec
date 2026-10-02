-- Manual intent is a separate invocation, never a rewrite of the scheduled
-- trigger or a substitute ProductID for a missing action prerequisite.
CREATE FUNCTION public.zasp_sa_manual_authority(o text,w text,e text,d text,v bigint,actor text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $authority$
DECLARE current_row public.zasp_security_agent_definitions%ROWTYPE;original public.zasp_security_agent_definition_versions%ROWTYPE;action_value text;binding_value jsonb:='{}';
BEGIN
 SELECT * INTO current_row FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 IF NOT FOUND OR current_row.activation NOT IN('supervised','autonomous') OR current_row.body->>'autonomy' IS DISTINCT FROM current_row.activation OR current_row.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR NOT COALESCE(current_row.body->'environment_ids' ? e,false) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual definition unavailable';END IF;
 SELECT * INTO original FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) FOR SHARE;
 IF NOT FOUND OR (original.activation,original.definition) IS DISTINCT FROM (current_row.activation,current_row.body) OR original.definition_digest IS DISTINCT FROM digest(convert_to(original.definition::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual original definition changed';END IF;
 PERFORM public.zasp_sa_export_principal(o,w,e,original.actor_id);
 PERFORM public.zasp_sa_export_principal(o,w,e,actor);
 IF jsonb_typeof(current_row.body->'allowed_actions') IS DISTINCT FROM 'array' OR jsonb_array_length(current_row.body->'allowed_actions')=0 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual actions unavailable';END IF;
 FOR action_value IN SELECT jsonb_array_elements_text(current_row.body->'allowed_actions') LOOP
  PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,action_value);
  CASE action_value
  WHEN 'run_test','rerun_test' THEN binding_value:=binding_value||jsonb_build_object(action_value,public.zasp_production_security_agent_run_context_test_binding(o,w,e,d,v));
  WHEN 'start_attack_lab' THEN binding_value:=binding_value||jsonb_build_object(action_value,public.zasp_sa_attack_lab_planner_binding(o,w,e,d,v));
  WHEN 'create_evidence_export' THEN IF current_row.body->>'verification_kind' IS DISTINCT FROM 'export' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual export verification unavailable';END IF;
  ELSE RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual action source prerequisite unavailable';
  END CASE;
 END LOOP;
 -- Re-read effective scope after all prerequisite waits, including group grants.
 PERFORM public.zasp_sa_export_principal(o,w,e,original.actor_id);PERFORM public.zasp_sa_export_principal(o,w,e,actor);
 RETURN jsonb_build_object('definition',current_row.body,'definition_digest',encode(original.definition_digest,'hex'),'bindings',binding_value);
END $authority$;

CREATE FUNCTION public.zasp_sa_manual_run(o text,w text,e text,d text,actor text,key_value text,v bigint,r text,audit_value text,correlation_value text,receipt_value text,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $run$
DECLARE authority_value jsonb;intent_value jsonb;digest_value bytea;trigger_value text;result_value jsonb;prior public.zasp_security_agent_request_receipts%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT public.zasp_sa_export_principal_ready('zasp_security_agent_api') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='manual admission principal unavailable';END IF;
 IF NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual admission release unavailable';END IF;
 IF NOT COALESCE(public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(d) AND public.zasp_valid_product_id(actor) AND public.zasp_valid_product_id(r) AND public.zasp_valid_product_id(audit_value) AND public.zasp_valid_product_id(correlation_value) AND public.zasp_valid_product_id(receipt_value) AND v BETWEEN 1 AND 1000000 AND length(key_value) BETWEEN 16 AND 128 AND key_value ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$',false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='manual admission identity rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 INSERT INTO public.zasp_security_agent_org_admissions(organization_id) VALUES(o) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM public.zasp_security_agent_org_admissions WHERE organization_id=o FOR UPDATE;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),o,w,e,actor,'runSecurityAgent',key_value),0));
 authority_value:=public.zasp_sa_manual_authority(o,w,e,d,v,actor);
 intent_value:=jsonb_build_object('schema_version',1,'kind','manual','organization_id',o,'workspace_id',w,'environment_id',e,'requester_id',actor,'definition_id',d,'definition_version',v,'idempotency_key',key_value);
 digest_value:=digest(convert_to(intent_value::text,'UTF8'),'sha256');trigger_value:=encode(digest_value,'hex');
 SELECT * INTO prior FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(o,w,e,actor,'runSecurityAgent',key_value);
 IF FOUND THEN
  IF (prior.resource_id,prior.expected_version,prior.intent,prior.intent_digest) IS DISTINCT FROM (d,v,intent_value,digest_value) OR prior.expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='manual admission replay conflict';END IF;
  IF public.zasp_sa_manual_provenance(o,w,e,prior.response->>'id') IS DISTINCT FROM prior.response->'manual_trigger' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual admission original receipt changed';END IF;
  IF public.zasp_sa_manual_authority(o,w,e,d,v,actor) IS DISTINCT FROM authority_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual admission authority changed';END IF;
  RETURN prior.response||jsonb_build_object('replayed',true);
 END IF;
 IF (SELECT count(*) FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) AND state IN('queued','planning','waiting_approval','running','verifying','contained')) >= (authority_value->'definition'->>'concurrency_limit')::integer THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual concurrency unavailable';END IF;
 IF public.zasp_sa_manual_authority(o,w,e,d,v,actor) IS DISTINCT FROM authority_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual admission authority changed';END IF;
 INSERT INTO public.zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(o,w,e,d,trigger_value,'manual',1,digest_value,r);
 INSERT INTO public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(o,w,e,r,d,v,trigger_value,actor,'queued');
 result_value:=jsonb_build_object('id',r,'agent_id',d,'state','queued','evidence_ids','[]'::jsonb,'manual_trigger',jsonb_build_object('kind','manual','intent_digest','sha256:'||trigger_value,'version',1),'definition_version',v,'version',1,'audit_id',audit_value,'correlation_id',correlation_value,'receipt_id',receipt_value,'replayed',false);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body) VALUES(o,w,e,audit_value,correlation_value,r,actor,'run_queued',digest_value,jsonb_build_object('run_id',r,'definition_id',d,'definition_version',v,'trigger_kind','manual','trigger_id',trigger_value,'trigger_version',1,'automatic',false));
 INSERT INTO public.zasp_security_agent_request_receipts(organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,resource_id,expected_version,intent,intent_digest,response,audit_id,correlation_id,receipt_id) VALUES(o,w,e,actor,'runSecurityAgent',key_value,d,v,intent_value,digest_value,result_value,audit_value,correlation_value,receipt_value);
 UPDATE public.zasp_security_agent_execution_state SET used_at=coalesce(used_at,clock_timestamp()) WHERE singleton;
 IF public.zasp_sa_manual_authority(o,w,e,d,v,actor) IS DISTINCT FROM authority_value OR NOT public.zasp_sa_export_readiness(expected_checksum,expected_fingerprint) OR public.zasp_sa_manual_provenance(o,w,e,r) IS DISTINCT FROM result_value->'manual_trigger' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual admission authority expired after write';END IF;
 RETURN result_value;
END $run$;
GRANT EXECUTE ON FUNCTION public.zasp_sa_manual_run(text,text,text,text,text,text,bigint,text,text,text,text,text,text) TO zasp_security_agent_api;

-- Historical public readers validate retained provenance without requiring a
-- still-enabled definition or a still-live request receipt TTL.
CREATE FUNCTION public.zasp_sa_manual_provenance(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $provenance$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;t public.zasp_security_agent_trigger_receipts%ROWTYPE;q public.zasp_security_agent_request_receipts%ROWTYPE;expected jsonb;metadata_value jsonb;
BEGIN
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO t FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='run original trigger unavailable';END IF;
 IF t.trigger_kind<>'manual' THEN
  IF NOT public.zasp_valid_product_id(t.trigger_id) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='run original trigger malformed';END IF;
  RETURN NULL;
 END IF;
 IF NOT public.zasp_valid_product_id(rr.requested_by) OR t.trigger_version<>1 OR t.trigger_id IS DISTINCT FROM encode(t.trigger_digest,'hex') OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) AND definition_digest=digest(convert_to(definition::text,'UTF8'),'sha256')) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual original trigger malformed';END IF;
 SELECT * INTO STRICT q FROM public.zasp_security_agent_request_receipts WHERE (organization_id,workspace_id,environment_id,principal_id,operation,resource_id,expected_version,intent_digest)=(o,w,e,rr.requested_by,'runSecurityAgent',rr.definition_id,rr.definition_version,t.trigger_digest) AND response->>'id'=r;
 expected:=jsonb_build_object('schema_version',1,'kind','manual','organization_id',o,'workspace_id',w,'environment_id',e,'requester_id',rr.requested_by,'definition_id',rr.definition_id,'definition_version',rr.definition_version,'idempotency_key',q.idempotency_key);
 metadata_value:=jsonb_build_object('kind','manual','intent_digest','sha256:'||t.trigger_id,'version',t.trigger_version);
 IF q.intent IS DISTINCT FROM expected OR q.intent_digest IS DISTINCT FROM digest(convert_to(expected::text,'UTF8'),'sha256') OR q.response->'manual_trigger' IS DISTINCT FROM metadata_value OR q.response->'evidence_ids' IS DISTINCT FROM '[]'::jsonb OR q.response->>'agent_id' IS DISTINCT FROM rr.definition_id OR (q.response->>'definition_version')::bigint IS DISTINCT FROM rr.definition_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='manual original intent changed';END IF;
 RETURN metadata_value;
END $provenance$;

CREATE FUNCTION public.zasp_sa_manual_fields(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $fields$
DECLARE value jsonb;
BEGIN
 value:=public.zasp_sa_manual_provenance(o,w,e,r);
 RETURN CASE WHEN value IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('manual_trigger',value) END;
END $fields$;
CREATE FUNCTION public.zasp_sa_manual_evidence(o text,w text,e text,r text,t text) RETURNS jsonb LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $evidence$
 SELECT CASE WHEN public.zasp_sa_manual_provenance(o,w,e,r) IS NULL THEN jsonb_build_array(t) ELSE '[]'::jsonb END
$evidence$;
CREATE FUNCTION public.zasp_sa_manual_recheck(o text,w text,e text,r text) RETURNS void LANGUAGE plpgsql VOLATILE SET search_path TO pg_catalog,public AS $recheck$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE;
BEGIN
 IF public.zasp_sa_manual_provenance(o,w,e,r) IS NULL THEN RETURN;END IF;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 PERFORM public.zasp_sa_manual_authority(o,w,e,rr.definition_id,rr.definition_version,rr.requested_by);
END $recheck$;

-- Preserve complete predecessor definitions and ACLs. These amendments use
-- original receipts only and leave every nonmanual branch unchanged.
DO $manual_readers$
DECLARE p record;d text;before_value text;anchor text;args text;rowname text;
BEGIN
 FOR p IN SELECT oid,proname FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN(
 'zasp_security_agent_claim_budgeted_runs','zasp_security_agent_run_page','zasp_security_agent_run_detail',
 'zasp_production_security_agent_existing_tests_approval_value','zasp_sa_attack_lab_approval_value','zasp_sa_export_approval_value') LOOP
  d:=pg_get_functiondef(p.oid);before_value:=d;
  IF p.proname='zasp_security_agent_claim_budgeted_runs' THEN
   anchor:='result_value:=result_value||jsonb_build_array(jsonb_build_object(';
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual claim predecessor changed';END IF;
   d:=replace(d,anchor,'PERFORM public.zasp_sa_manual_recheck(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id);'||chr(10)||anchor);
   anchor:='(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id))));';
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual claim envelope changed';END IF;
   d:=replace(d,anchor,'(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id)))||public.zasp_sa_manual_fields(run_row.organization_id,run_row.workspace_id,run_row.environment_id,run_row.run_id));');
  ELSIF p.proname='zasp_security_agent_run_page' THEN
   d:=replace(d,'jsonb_build_array(trigger_id)','public.zasp_sa_manual_evidence(organization_value,workspace_value,environment_value,run_id,trigger_id)');
   d:=replace(d,'''version'',version) ORDER BY','''version'',version)||public.zasp_sa_manual_fields(organization_value,workspace_value,environment_value,run_id) ORDER BY');
  ELSIF p.proname='zasp_security_agent_run_detail' THEN
   d:=replace(d,'jsonb_build_array(run.trigger_id)','public.zasp_sa_manual_evidence(organization_value,workspace_value,environment_value,run.run_id,run.trigger_id)');
   d:=replace(d,'''version'',run.version),','''version'',run.version)||public.zasp_sa_manual_fields(organization_value,workspace_value,environment_value,run.run_id),');
   d:=replace(d,'run.run_id,run.trigger_id)) ORDER BY','run.run_id,run.trigger_id))||public.zasp_sa_manual_fields(organization_value,workspace_value,environment_value,run.run_id) ORDER BY');
  ELSE
   rowname:=CASE p.proname WHEN 'zasp_sa_export_approval_value' THEN 'rr' WHEN 'zasp_sa_attack_lab_approval_value' THEN 'r' ELSE 'run_row' END;
   d:=replace(d,'jsonb_build_array('||rowname||'.trigger_id)','public.zasp_sa_manual_evidence(o,w,e,'||rowname||'.run_id,'||rowname||'.trigger_id)');
   -- Only the final direct value needs decoration. Delegated values decorate
   -- themselves in their own family; neither stored decisions nor plans change.
   anchor:=CASE p.proname WHEN 'zasp_sa_attack_lab_approval_value' THEN '''attack_lab'',p.plan->''steps''->0->''attack_lab'');' ELSE rowname||'.run_id,'||rowname||'.trigger_id));' END;
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual approval predecessor changed';END IF;
   d:=replace(d,anchor,left(anchor,length(anchor)-1)||'||public.zasp_sa_manual_fields(o,w,e,'||rowname||'.run_id);');
  END IF;
  IF d=before_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual reader predecessor changed';END IF;
  IF NOT starts_with(p.proname,'zasp_sa_export_') AND NOT EXISTS(SELECT 1 FROM zasp_sa_export_prior.functions WHERE signature=p.oid::regprocedure::text OR signature='public.'||p.oid::regprocedure::text) THEN PERFORM public.zasp_sa_export_save(p.oid::regprocedure::text);END IF;
  EXECUTE d;
 END LOOP;
END $manual_readers$;

DO $manual_planning$
DECLARE p record;d text;before_value text;anchor text;
BEGIN
 FOR p IN SELECT oid,proname FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname IN(
 'zasp_sa_export_planner_context_core','zasp_sa_export_prepare_core','zasp_sa_export_authorize',
 'zasp_production_security_agent_existing_tests_planner_context','zasp_production_security_agent_existing_tests_recheck_context',
 'zasp_sa_attack_lab_planner_context','zasp_sa_attack_lab_recheck_context',
 'zasp_production_security_agent_existing_tests_prepare_core','zasp_sa_attack_lab_prepare_core',
 'zasp_security_agent_test_dispatch','zasp_production_security_agent_existing_tests_authorize_step','zasp_sa_attack_lab_authorize') LOOP
  d:=pg_get_functiondef(p.oid);before_value:=d;
  IF p.proname='zasp_sa_export_planner_context_core' THEN
   anchor:='IF t.trigger_kind IS DISTINCT FROM d.definition->>''trigger_kind'' OR t.trigger_kind NOT IN(''finding'',''attack_path'',''runtime_decision'') THEN';
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual export context predecessor changed';END IF;
   d:=replace(d,anchor,'IF t.trigger_kind=''manual'' THEN PERFORM public.zasp_sa_manual_recheck(o,w,e,r); ELSIF t.trigger_kind IS DISTINCT FROM d.definition->>''trigger_kind'' OR t.trigger_kind NOT IN(''finding'',''attack_path'',''runtime_decision'') THEN');
   d:=replace(d,'''attempt'',rr.attempt),''maximum_steps''','''attempt'',rr.attempt)||public.zasp_sa_manual_fields(o,w,e,r),''maximum_steps''');
   d:=replace(d,'PERFORM public.zasp_sa_export_planner_source_authority(o,w,e,r,selection_value);','PERFORM public.zasp_sa_manual_recheck(o,w,e,r); PERFORM public.zasp_sa_export_planner_source_authority(o,w,e,r,selection_value);');
  ELSIF p.proname IN('zasp_sa_export_prepare_core','zasp_sa_export_authorize') THEN
   d:=replace(d,'jsonb_build_array(rr.trigger_id)','public.zasp_sa_manual_evidence(o,w,e,r,rr.trigger_id)');
  ELSIF p.proname IN('zasp_production_security_agent_existing_tests_prepare_core','zasp_sa_attack_lab_prepare_core') THEN
   d:=replace(d,'jsonb_build_array(run_row.trigger_id)','public.zasp_sa_manual_evidence(o,w,e,r,run_row.trigger_id)');
  ELSIF p.proname IN('zasp_production_security_agent_existing_tests_authorize_step','zasp_sa_attack_lab_authorize') THEN
   IF p.proname='zasp_sa_attack_lab_authorize' THEN
    d:=replace(d,'OR public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,d.body->>''trigger_source'',t.trigger_version) IS DISTINCT FROM jsonb_build_object(''version'',t.trigger_version,''digest'',encode(t.trigger_digest,''hex''))','OR t.trigger_kind<>''manual'' AND public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,d.body->>''trigger_source'',t.trigger_version) IS DISTINCT FROM jsonb_build_object(''version'',t.trigger_version,''digest'',encode(t.trigger_digest,''hex''))');
   END IF;
   -- Both private authorities are called again after writes by their dispatchers.
   d:=replace(d,'BEGIN'||chr(10),'BEGIN'||chr(10)||' PERFORM public.zasp_sa_manual_recheck(o,w,e,r);'||chr(10));
  ELSE
   d:=replace(d,'trigger_row.trigger_kind IS DISTINCT FROM definition_row.body->>''trigger_kind''','trigger_row.trigger_kind<>''manual'' AND trigger_row.trigger_kind IS DISTINCT FROM definition_row.body->>''trigger_kind''');
   anchor:='IF trigger_row.trigger_kind=''finding'' THEN';
   IF strpos(d,anchor)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual planner source predecessor changed';END IF;
   d:=replace(d,anchor,'IF trigger_row.trigger_kind=''manual'' THEN PERFORM public.zasp_sa_manual_recheck(o,w,e,r); PERFORM 1; ELSIF trigger_row.trigger_kind=''finding'' THEN');
   d:=replace(d,'''attempt'',run_row.attempt),','''attempt'',run_row.attempt)||public.zasp_sa_manual_fields(o,w,e,r),');
   IF p.proname<>'zasp_security_agent_test_dispatch' THEN
    d:=replace(d,'RETURN jsonb_build_object(''context'',context_value,','PERFORM public.zasp_sa_manual_recheck(o,w,e,r);'||chr(10)||' RETURN jsonb_build_object(''context'',context_value,');
   END IF;
  END IF;
  IF d=before_value THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='manual preparation predecessor changed';END IF;
  IF NOT starts_with(p.proname,'zasp_sa_export_') AND NOT EXISTS(SELECT 1 FROM zasp_sa_export_prior.functions WHERE signature=p.oid::regprocedure::text OR signature='public.'||p.oid::regprocedure::text) THEN PERFORM public.zasp_sa_export_save(p.oid::regprocedure::text);END IF;
  EXECUTE d;
 END LOOP;
END $manual_planning$;
