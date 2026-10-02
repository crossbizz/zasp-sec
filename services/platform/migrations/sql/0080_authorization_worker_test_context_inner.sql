-- Fixed same-call readers. Native contexts remain unchanged for every other
-- caller; only callers with retained entry and exit fences use these copies.
DO $test_context_inner$ DECLARE d text;needle text;n text;BEGIN
 -- These two grant readers are called only by the fixed contexts below. Keep
 -- isolation, schema locks, own principal, grant/history/target and audit checks.
 FOREACH n IN ARRAY ARRAY['authorize','service_current'] LOOP
  d:=pg_get_functiondef(CASE n WHEN 'authorize' THEN 'zasp_temporal74.authorize(text,text,text,text,bigint)'::regprocedure ELSE 'zasp_temporal74.service_current(text,text,text,text,bigint)'::regprocedure END);
  needle:='FUNCTION zasp_temporal74.'||n||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner grant declaration changed';END IF;
  d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.test74_'||n||'_inner(');
  IF n='authorize' THEN
   needle:=$old$IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service authority principal rejected';END IF;$old$;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner grant principal entry changed';END IF;
   d:=replace(d,needle,$new$IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service authority principal rejected';END IF;$new$);
  ELSE
   needle:=$old$IF NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='service authority principal rejected';END IF;$old$;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner current grant entry changed';END IF;
   d:=replace(d,needle,'');
  END IF;
  EXECUTE d;
 END LOOP;

 FOREACH n IN ARRAY ARRAY['context','context_parent'] LOOP
  d:=pg_get_functiondef(CASE n WHEN 'context' THEN 'zasp_temporal74.context(text,text,text,text)'::regprocedure ELSE 'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure END);
  needle:='FUNCTION zasp_temporal74.'||n||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner context declaration changed';END IF;
  d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.test74_'||n||'_inner(');
  needle:='zasp_authorization80_worker.runtime_trigger(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner context trigger pair changed';END IF;
  d:=replace(d,needle,'zasp_authorization80_worker.runtime_trigger_inner(');
  needle:='PERFORM zasp_temporal74.'||CASE n WHEN 'context' THEN 'authorize' ELSE 'service_current' END||'(o,w,e,rr.definition_id,rr.definition_version);';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test inner context grant caller changed';END IF;
  -- Only runtime facts have the enclosing runtime_source exit fence. Preserve
  -- the original native grant reader on every other trusted trigger kind.
  EXECUTE replace(d,needle,'IF t.trigger_kind=''runtime_decision'' THEN PERFORM zasp_authorization80_worker.test74_'||CASE n WHEN 'context' THEN 'authorize' ELSE 'service_current' END||'_inner(o,w,e,rr.definition_id,rr.definition_version);ELSE '||needle||'END IF;');
 END LOOP;

 d:=pg_get_functiondef('zasp_authorization80_worker.test74_private_facts(boolean,jsonb,boolean,jsonb)'::regprocedure);
 needle:=$entry$IF compensation IS NULL OR execution IS NULL OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test source reader rejected';END IF;$entry$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test context facts entry changed';END IF;
 needle:='runtime_value:=zasp_authorization80_worker.runtime_source_after_entry(x.organization_id,x.workspace_id,x.environment_id,x.run_id);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test context facts exit reader changed';END IF;
 FOREACH n IN ARRAY ARRAY['context','context_parent'] LOOP
  needle:='zasp_temporal74.'||n||'(';
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test facts context caller changed';END IF;
  d:=replace(d,needle,'zasp_authorization80_worker.test74_'||n||'_inner(');
 END LOOP;
 EXECUTE d;

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal74.load_plan(jsonb)';
 needle:=$entry$IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor authority unavailable';END IF;$entry$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test load context entry changed';END IF;
 needle:=$exit$OR zasp_temporal74.context(o,w,e,r) IS DISTINCT FROM job.context_value OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='executor planning authority changed';END IF;$exit$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test load context exit changed';END IF;
 needle:='zasp_temporal74.context(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test load context pair changed';END IF;
 EXECUTE replace(d,needle,'zasp_authorization80_worker.test74_context_inner(');

 d:=pg_get_functiondef('zasp_temporal74.plan(jsonb)'::regprocedure);
 needle:=$entry$IF NOT zasp_temporal68.principal_ready('zasp_temporal_executor') OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='executor planning unavailable';END IF;$entry$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test plan context entry changed';END IF;
 needle:=$exit$IF NOT zasp_temporal74.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='test planning authority changed after final lookup';END IF;$exit$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test plan context exit changed';END IF;
 needle:='zasp_temporal74.context(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='test plan context pair changed';END IF;
 EXECUTE replace(d,needle,'zasp_authorization80_worker.test74_context_inner(');
END $test_context_inner$;
