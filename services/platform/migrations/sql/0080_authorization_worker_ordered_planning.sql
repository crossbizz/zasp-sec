-- Reuse the reviewed closed proof and seven-field recovery protocol. Only the
-- exact native family and its source reader differ; no caller-selected SQL.
DO $ordered_planning$ DECLARE d text;n text;needle text;BEGIN
 FOREACH n IN ARRAY ARRAY['planning78_source','require_planning78','planning78_recovery_result','planning78_recovery'] LOOP
  SELECT pg_get_functiondef(oid) INTO STRICT d FROM pg_proc WHERE pronamespace='zasp_authorization80_worker'::regnamespace AND proname=n;
  d:=replace(replace(replace(d,'planning78','planning68'),'zasp_temporal78.','zasp_temporal68.'),'finding.planning.','ordered68.planning.');
  IF n='planning78_source' THEN
   needle:='zasp_temporal68.run_owners';
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered owner protocol changed';END IF;
   d:=replace(d,needle,'zasp_temporal66.run_owners');
   needle:=$old$ IF compensation THEN reference_value:=reference_value||jsonb_build_object('reason','workflow_failed');END IF;
 f:=zasp_authorization80_worker.finding_source(CASE WHEN compensation THEN 'finding.cleanup' ELSE 'finding.planning' END,reference_value);$old$;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered source protocol changed';END IF;
   d:=replace(d,needle,' f:=zasp_authorization80_worker.ordered68_source(compensation,reference_value);');
  END IF;
  EXECUTE d;
 END LOOP;
END $ordered_planning$;

INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal68.plan(jsonb)'::regprocedure,'zasp_temporal68.status(jsonb)'::regprocedure);
DO $ordered_boundaries$ DECLARE p record;d text;needle text:=E'BEGIN\n';phase text;callee text;return_value text;BEGIN
 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal68.plan(jsonb)','zasp_temporal68.status(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' OR(length(p.definition)-length(replace(p.definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered planning predecessor rejected';END IF;
  phase:=CASE p.signature WHEN 'zasp_temporal68.plan(jsonb)' THEN 'q->>''operation''' ELSE '''state''' END;
  d:=replace(p.definition,needle,needle||' PERFORM zasp_authorization80_worker.require_planning68('||phase||',q);'||E'\n');
  IF p.signature='zasp_temporal68.plan(jsonb)' THEN
   FOREACH callee IN ARRAY ARRAY['recover_plan','record_late_usage'] LOOP
    IF(length(d)-length(replace(d,'RETURN zasp_temporal68.'||callee||'(q);','')))/length('RETURN zasp_temporal68.'||callee||'(q);')<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered recovery predecessor rejected';END IF;
    d:=replace(d,'RETURN zasp_temporal68.'||callee||'(q);','RETURN zasp_authorization80_worker.planning68_recovery_result(zasp_temporal68.'||callee||'(q));');
   END LOOP;
  ELSE
   -- Planning authorization does not authorize later Block/effect details.
   -- Keep the original status validation/locking work, but narrow its only
   -- public return to the current-authorized planner job for this profile.
   return_value:=$return$ RETURN jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'run_id',r,'definition_version',rr.definition_version,'run_state',rr.state,'run_version',rr.version,'admitted',projection->'admitted','planning',CASE WHEN j.run_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(j) END,'effects',effects_value,'projection',projection);$return$;
   IF(length(d)-length(replace(d,return_value,'')))/length(return_value)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='ordered planner state return changed';END IF;
   d:=replace(d,return_value,$return$ RETURN jsonb_build_object('planning',CASE WHEN j.run_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(j) END);$return$);
  END IF;
  EXECUTE d;
 END LOOP;
END $ordered_boundaries$;
