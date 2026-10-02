-- Install after ordered planning/effects. These three compensation-only
-- entries consume retained admission, not a newly minted planning grant.
CREATE FUNCTION zasp_authorization80_worker.ordered69_source(phase text,q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $lifecycle_source$
DECLARE o text;w text;e text;r text;k text;
 x zasp_temporal66.run_owners%ROWTYPE;c zasp_temporal65.commands%ROWTYPE;m zasp_temporal65.commands%ROWTYPE;
 rr public.zasp_security_agent_runs%ROWTYPE;tr public.zasp_security_agent_trigger_receipts%ROWTYPE;
 h public.zasp_security_agent_definition_versions%ROWTYPE;receipt public.zasp_security_agent_request_receipts%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;
 start_receipt_digest text;decision_digest text;source_value jsonb;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION USING ERRCODE='25001',MESSAGE='ordered lifecycle requires read committed';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal69.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered lifecycle principal rejected';END IF;
 IF phase IS NULL OR phase NOT IN('inspect','message','stop') OR octet_length(q::text)>4096 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered lifecycle phase rejected';END IF;
 IF phase='message' THEN
  IF NOT zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','run_id','event_id','decision_id','kind']) OR NOT COALESCE(q->>'kind' IN('approval','cancel'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered lifecycle message rejected';END IF;
  FOREACH k IN ARRAY ARRAY['event_id','decision_id'] LOOP
   IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered lifecycle decision rejected';END IF;
  END LOOP;
 ELSE
  IF NOT zasp_sa_multistep_prior.closed(q,CASE WHEN phase='stop' THEN ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest','reason'] ELSE ARRAY['organization_id','workspace_id','environment_id','run_id','definition_version','input_digest'] END)
   OR jsonb_typeof(q->'definition_version') IS DISTINCT FROM 'number' OR NOT COALESCE(q->>'definition_version'~'^([1-9][0-9]{0,5}|1000000)$',false)
   OR jsonb_typeof(q->'input_digest') IS DISTINCT FROM 'string' OR NOT COALESCE(q->>'input_digest'~'^[a-f0-9]{64}$',false)
   OR phase='stop' AND NOT COALESCE(q->>'reason' IN('workflow_cancelled','workflow_deadline','workflow_failed'),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered lifecycle start rejected';END IF;
 END IF;
 FOREACH k IN ARRAY ARRAY['organization_id','workspace_id','environment_id','run_id'] LOOP
  IF jsonb_typeof(q->k) IS DISTINCT FROM 'string' OR NOT COALESCE(public.zasp_valid_product_id(q->>k),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='ordered lifecycle scope rejected';END IF;
 END LOOP;
 o:=q->>'organization_id';w:=q->>'workspace_id';e:=q->>'environment_id';r:=q->>'run_id';
 PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered lifecycle organization absent';END IF;
 -- Match retained68 status exactly before taking any run/owner/command row.
 -- A predecessor reader can hold this advisory lock without an organization
 -- lock; it must never wait on a row already held by this source.
 PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));
 PERFORM 1 FROM public.zasp_security_agent_run_budgets WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO rr FROM public.zasp_security_agent_runs WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR UPDATE;
 SELECT * INTO x FROM zasp_temporal66.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 SELECT * INTO c FROM zasp_temporal65.commands WHERE(organization_id,workspace_id,environment_id,run_id,kind)=(o,w,e,r,'start') FOR SHARE;
 IF x.run_id IS NULL OR c.run_id IS NULL OR rr.run_id IS NULL OR x.execution_owner<>'temporal' OR c.execution_owner<>'temporal'
  OR(x.definition_version,x.input_digest) IS DISTINCT FROM(c.definition_version,c.input_digest) OR rr.definition_version IS DISTINCT FROM x.definition_version
  OR rr.lease_owner IS NOT NULL OR rr.lease_token IS NOT NULL OR rr.lease_expires_at IS NOT NULL
  OR phase<>'message' AND(q->'definition_version',q->>'input_digest') IS DISTINCT FROM(to_jsonb(x.definition_version),x.input_digest) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered lifecycle retained owner changed';END IF;
 SELECT * INTO tr FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(o,w,e,r,rr.definition_id,rr.trigger_id) FOR SHARE;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,rr.definition_id,rr.definition_version) FOR SHARE;
 IF tr.run_id IS NULL OR tr.trigger_kind NOT IN('finding','attack_path') OR encode(tr.trigger_digest,'hex') IS DISTINCT FROM x.input_digest
  OR r IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',rr.definition_id||chr(31)||rr.trigger_id||chr(31)||tr.trigger_version::text)
  OR h.definition_id IS NULL OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') OR h.definition->'allowed_actions' IS DISTINCT FROM '["create_temporary_policy","run_test"]'::jsonb THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered lifecycle historical admission changed';END IF;
 SELECT * INTO receipt FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,receipt_id,operation)=(o,w,e,c.event_id,'runSecurityAgent') FOR SHARE;
 SELECT * INTO a FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id,run_id)=(o,w,e,receipt.audit_id,r) FOR SHARE;
 IF receipt.receipt_id IS NULL OR a.audit_id IS NULL OR(a.actor_id,receipt.principal_id) IS DISTINCT FROM(rr.requested_by,rr.requested_by)
  OR receipt.intent_digest IS DISTINCT FROM digest(convert_to(receipt.intent::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered lifecycle committed start absent';END IF;
 start_receipt_digest:=encode(digest(convert_to(jsonb_build_array(receipt.receipt_id,receipt.principal_id,receipt.audit_id,encode(receipt.intent_digest,'hex'),encode(a.event_digest,'hex'))::text,'UTF8'),'sha256'),'hex');
 IF phase='message' THEN
  SELECT * INTO m FROM zasp_temporal65.commands WHERE(organization_id,workspace_id,environment_id,run_id,event_id,decision_id,kind,execution_owner)=(o,w,e,r,q->>'event_id',q->>'decision_id',q->>'kind','temporal') FOR SHARE;
  SELECT * INTO receipt FROM public.zasp_security_agent_request_receipts WHERE(organization_id,workspace_id,environment_id,receipt_id,operation)=(o,w,e,m.decision_id,CASE m.kind WHEN 'approval' THEN 'decideSecurityAgentApproval' ELSE 'cancelSecurityAgentRun' END) FOR SHARE;
  SELECT * INTO a FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id,run_id)=(o,w,e,receipt.audit_id,r) FOR SHARE;
  IF m.run_id IS NULL OR receipt.receipt_id IS NULL OR a.audit_id IS NULL OR a.actor_id IS DISTINCT FROM receipt.principal_id OR m.definition_version IS DISTINCT FROM c.definition_version
   OR receipt.intent_digest IS DISTINCT FROM digest(convert_to(receipt.intent::text,'UTF8'),'sha256') OR m.input_digest IS DISTINCT FROM encode(receipt.intent_digest,'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='ordered lifecycle committed decision absent';END IF;
  decision_digest:=encode(digest(convert_to(jsonb_build_array(m.event_id,m.decision_id,m.kind,m.definition_version,m.input_digest,receipt.principal_id,receipt.audit_id,encode(a.event_digest,'hex'))::text,'UTF8'),'sha256'),'hex');
 END IF;
 source_value:=jsonb_build_array(x.execution_owner,rr.definition_id,x.definition_version,x.input_digest,c.event_id,tr.trigger_kind,tr.trigger_id,tr.trigger_version,encode(h.definition_digest,'hex'),start_receipt_digest,decision_digest);
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal69.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered lifecycle authority changed after locks';END IF;
 RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_id',rr.definition_id,'definition_version',x.definition_version,'definition_digest',encode(h.definition_digest,'hex'),'source_digest',encode(digest(convert_to(source_value::text,'UTF8'),'sha256'),'hex'),'request_digest',encode(digest(convert_to(q::text,'UTF8'),'sha256'),'hex'),'lifecycle_phase',phase,'checks','[]'::jsonb,'session_user',session_user);
END $lifecycle_source$;

-- Exact current proof parser, restricted to compensation and these three
-- operations. Acquire the shared schema lock before its organization lock.
DO $ordered_lifecycle_proof$ DECLARE d text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.require_planning68(text,jsonb)'::regprocedure);
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_authorization80_worker.require_planning68(', 'FUNCTION zasp_authorization80_worker.require_ordered69(');
 d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_authorization80_worker.planning68_source(', 'zasp_authorization80_worker.ordered69_source(');
 d:=zasp_authorization80_worker.ordered62_replace(d,'ordered68.planning.','ordered69.');
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$('state','load','prepare','start','result','settle','artifacts','admit','reconcile','late_usage','recovery')$old$,$new$('inspect','message','stop')$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,$old$CASE WHEN phase IN('reconcile','late_usage','recovery') THEN 'captured-compensation' ELSE 'worker-forward' END$old$,$new$'captured-compensation'$new$);
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n PERFORM pg_advisory_xact_lock_shared(hashtextextended(''zasp-schema-migrations'',0));\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,E' RETURNS void\n',E' RETURNS jsonb\n');
 d:=zasp_authorization80_worker.ordered62_replace(d,'EXCEPTION WHEN data_exception THEN',E' RETURN proof;\nEXCEPTION WHEN data_exception THEN');
 EXECUTE d;
END $ordered_lifecycle_proof$;

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal69.inspect(jsonb)'::regprocedure,'zasp_temporal69.inspect_message(jsonb)'::regprocedure,'zasp_temporal69.stop(jsonb)'::regprocedure,'zasp_temporal69.stop_test(jsonb)'::regprocedure);
DO $ordered_lifecycle_copies$ DECLARE d text;p record;needle text;BEGIN
 -- The effects module is an explicit prerequisite, never a live-body fallback.
 PERFORM 'zasp_authorization80_worker.ordered68_effect_read(jsonb)'::regprocedure;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal68.status(jsonb)' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
 EXECUTE zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.status(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_status_inner(q jsonb)');
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal68.plan(jsonb)' AND owner_name='zasp_discovery_authority' AND acl='{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}';
 d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal68.plan(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_reconcile_inner(q jsonb)');
 d:=zasp_authorization80_worker.ordered62_replace(d,E'BEGIN\n',E'BEGIN\n IF q->>''operation'' IS DISTINCT FROM ''reconcile'' OR q->''payload'' IS DISTINCT FROM ''{}''::jsonb THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''ordered lifecycle reconcile rejected'';END IF;\n');
 EXECUTE d;
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal69.inspect(jsonb)','zasp_temporal69.inspect_message(jsonb)','zasp_temporal69.stop(jsonb)','zasp_temporal69.stop_test(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered lifecycle predecessor owner changed';END IF;
  d:=p.definition;
  CASE p.signature
  WHEN 'zasp_temporal69.inspect(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered inspect predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal69.inspect(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_inspect_inner(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal68.status(q-', 'zasp_authorization80_worker.ordered69_status_inner(q-');
  WHEN 'zasp_temporal69.inspect_message(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered message predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal69.inspect_message(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_message_inner(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,$old$zasp_temporal68.principal_ready('zasp_temporal_executor')$old$,$new$zasp_temporal68.principal_ready('zasp_temporal_compensation')$new$);
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal69.inspect(', 'zasp_authorization80_worker.ordered69_inspect_inner(');
  WHEN 'zasp_temporal69.stop(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered stop predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal69.stop(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_stop_inner(q jsonb)');
   needle:='zasp_temporal69.inspect(';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered stop inspect edge changed';END IF;
   d:=replace(d,needle,'zasp_authorization80_worker.ordered69_inspect_inner(');
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal68.plan(', 'zasp_authorization80_worker.ordered69_reconcile_inner(');
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal69.stop_test(', 'zasp_authorization80_worker.ordered69_stop_test_inner(');
  WHEN 'zasp_temporal69.stop_test(jsonb)' THEN
   IF p.acl<>'{zasp_discovery_authority=X/zasp_discovery_authority}' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered stop test predecessor ACL changed';END IF;
   d:=zasp_authorization80_worker.ordered62_replace(d,'FUNCTION zasp_temporal69.stop_test(q jsonb)','FUNCTION zasp_authorization80_worker.ordered69_stop_test_inner(q jsonb)');
   d:=zasp_authorization80_worker.ordered62_replace(d,'zasp_temporal68.effect(', 'zasp_authorization80_worker.ordered68_effect_read(');
  END CASE;
  EXECUTE d;
 END LOOP;
END $ordered_lifecycle_copies$;

CREATE FUNCTION zasp_authorization80_worker.ordered69_finish(proof jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $lifecycle_finish$
DECLARE now_ms bigint;BEGIN
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal69.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_compensation') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered lifecycle authority changed';END IF;
 now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
 IF NOT COALESCE(proof->>'purpose'='captured-compensation' AND proof->>'session_user'=session_user AND(proof->>'issued_at')::bigint<=now_ms+5000 AND(proof->>'expires_at')::bigint>now_ms AND(proof->>'expires_at')::bigint-(proof->>'issued_at')::bigint BETWEEN 1 AND 60000,false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='ordered lifecycle authority expired';END IF;
END $lifecycle_finish$;
CREATE FUNCTION zasp_authorization80_worker.ordered69_inspect(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $inspect$
DECLARE proof jsonb;result_value jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered69('inspect',q);
 result_value:=zasp_authorization80_worker.ordered69_inspect_inner(q);
 PERFORM zasp_authorization80_worker.ordered69_finish(proof);
 RETURN result_value;
END $inspect$;
CREATE FUNCTION zasp_authorization80_worker.ordered69_message(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $message$
DECLARE proof jsonb;result_value jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered69('message',q);
 result_value:=zasp_authorization80_worker.ordered69_message_inner(q);
 PERFORM zasp_authorization80_worker.ordered69_finish(proof);
 RETURN result_value;
END $message$;
CREATE FUNCTION zasp_authorization80_worker.ordered69_stop(q jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $stop$
DECLARE proof jsonb;result_value jsonb;BEGIN
 proof:=zasp_authorization80_worker.require_ordered69('stop',q);
 result_value:=zasp_authorization80_worker.ordered69_stop_inner(q);
 PERFORM zasp_authorization80_worker.ordered69_finish(proof);
 RETURN result_value;
END $stop$;
DO $lifecycle_owners$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace AND proname IN('ordered69_source','require_ordered69','ordered69_status_inner','ordered69_reconcile_inner','ordered69_inspect_inner','ordered69_message_inner','ordered69_stop_inner','ordered69_stop_test_inner','ordered69_finish','ordered69_inspect','ordered69_message','ordered69_stop') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $lifecycle_owners$;
GRANT EXECUTE ON FUNCTION zasp_authorization80_worker.ordered69_source(text,jsonb),zasp_authorization80_worker.ordered69_inspect(jsonb),zasp_authorization80_worker.ordered69_message(jsonb),zasp_authorization80_worker.ordered69_stop(jsonb) TO zasp_temporal_compensation;
