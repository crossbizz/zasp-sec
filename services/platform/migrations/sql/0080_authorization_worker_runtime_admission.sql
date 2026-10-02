-- Runtime Test admission preserves two different source protocols. This is
-- private source validation, never current forward-worker authorization.
INSERT INTO zasp_authorization80_worker.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
 WHERE oid IN('zasp_temporal77.rules_capable(jsonb)'::regprocedure,'zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)'::regprocedure,'zasp_temporal78.admit_occurrence(jsonb)'::regprocedure,
 'zasp_temporal78.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure,
 'zasp_temporal75.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure,
 'zasp_temporal74.takeover(text,text,text,text)'::regprocedure,'zasp_temporal74.context(text,text,text,text)'::regprocedure,
 'zasp_temporal74.context_parent(text,text,text,text,jsonb)'::regprocedure,'zasp_temporal74.load_plan(jsonb)'::regprocedure);

CREATE FUNCTION zasp_authorization80_worker.runtime_occurrence_match(o text,w text,e text,event_value text,b jsonb) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $match$
DECLARE before_value jsonb;after_value jsonb;BEGIN
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready()
 OR b->>'trigger_kind' IS DISTINCT FROM 'runtime_decision' OR b->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic'
 OR NOT zasp_temporal77.rules_valid(b) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime occurrence contract rejected';END IF;
 -- Callers take the authorization organization lock before any source lock.
 before_value:=zasp_temporal77.source_match(o,w,e,event_value,b,clock_timestamp());
 IF before_value IS NULL THEN
  IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime occurrence catalog changed';END IF;
  RETURN NULL;
 END IF;
 IF before_value->>'kind'<>'runtime_decision' OR jsonb_array_length(before_value#>'{evidence,events}') NOT BETWEEN 1 AND 100
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime occurrence evidence changed';END IF;
 PERFORM 1 FROM public.zasp_gateway_devices d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e)
 AND d.id IN(SELECT x->>'device_id' FROM jsonb_array_elements(before_value#>'{evidence,events}') x UNION SELECT before_value#>>'{evidence,anchor,device_id}') ORDER BY d.id FOR SHARE;
 PERFORM 1 FROM public.zasp_gateway_credentials c JOIN public.zasp_runtime_gateway_events v
 ON(v.organization_id,v.workspace_id,v.environment_id,v.device_id,v.credential_id)=(c.organization_id,c.workspace_id,c.environment_id,c.device_id,c.id)
 WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e)
 AND v.event_id IN(SELECT x->>'event_id' FROM jsonb_array_elements(before_value#>'{evidence,events}') x UNION SELECT before_value#>>'{evidence,anchor,event_id}')
 ORDER BY c.device_id,c.id FOR SHARE OF c;
 PERFORM 1 FROM public.zasp_runtime_gateway_events v WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e)
 AND v.event_id IN(SELECT x->>'event_id' FROM jsonb_array_elements(before_value#>'{evidence,events}') x UNION SELECT before_value#>>'{evidence,anchor,event_id}') ORDER BY v.event_id FOR SHARE;
 PERFORM 1 FROM zasp_temporal77.runtime_evaluations a WHERE(a.organization_id,a.workspace_id,a.environment_id)=(o,w,e)
 AND a.event_id IN(SELECT x->>'event_id' FROM jsonb_array_elements(before_value#>'{evidence,events}') x UNION SELECT before_value#>>'{evidence,anchor,event_id}') ORDER BY a.event_id FOR SHARE;
 after_value:=zasp_temporal77.source_match(o,w,e,event_value,b,clock_timestamp());
 IF after_value IS DISTINCT FROM before_value OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready()
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime occurrence changed under lock';END IF;
 RETURN after_value;
END $match$;

CREATE FUNCTION zasp_authorization80_worker.runtime_trigger(o text,w text,e text,d text,v bigint,r text,k text,t text,s text,tv bigint) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $trigger$
DECLARE h public.zasp_security_agent_definition_versions%ROWTYPE;a zasp_temporal77.occurrences%ROWTYPE;source_value zasp_temporal77.source_events%ROWTYPE;matched jsonb;BEGIN
 SELECT * INTO STRICT h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) FOR SHARE;
 IF h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime historical definition changed';END IF;
 IF h.definition->>'trigger_kind'<>'runtime_decision' OR h.definition->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic' THEN
  RETURN public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,s,tv);
 END IF;
 -- A configured source never falls back to session/latest-event semantics.
 IF k<>'runtime_decision' OR h.definition->>'trigger_source' IS DISTINCT FROM s
 OR h.definition->'allowed_actions' NOT IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)
 THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='configured runtime identity rejected';END IF;
 SELECT occurrence.* INTO STRICT a FROM zasp_temporal77.occurrences occurrence JOIN zasp_temporal77.source_events src USING(organization_id,workspace_id,environment_id,event_id)
 WHERE(occurrence.organization_id,occurrence.workspace_id,occurrence.environment_id,occurrence.definition_id,occurrence.definition_version,occurrence.run_id,occurrence.disposition,src.source_kind,src.source_id,src.source_version)=(o,w,e,d,v,r,'admitted',k,t,tv) FOR SHARE OF occurrence,src;
 SELECT * INTO STRICT source_value FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,a.event_id);
 IF a.definition_digest IS DISTINCT FROM h.definition_digest OR a.snapshot_digest IS DISTINCT FROM digest(convert_to(a.snapshot::text,'UTF8'),'sha256')
 OR r IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',concat_ws(chr(31),d,v,k,t,tv))
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='configured runtime capture changed';END IF;
 matched:=zasp_authorization80_worker.runtime_occurrence_match(o,w,e,a.event_id,h.definition);
 IF matched IS NULL OR matched->'evidence' IS DISTINCT FROM a.snapshot OR decode(matched->>'digest','hex') IS DISTINCT FROM a.snapshot_digest
 OR(matched->>'trigger_id',(matched->>'version')::bigint) IS DISTINCT FROM(t,tv)
 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='configured runtime source changed';END IF;
 RETURN jsonb_build_object('version',tv,'digest',encode(a.snapshot_digest,'hex'));
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='configured runtime provenance missing';
END $trigger$;

DO $runtime_admission$ DECLARE d text;needle text;replacement text;p record;BEGIN
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal77.put_source(text,text,text,text,text,bigint,timestamp with time zone)';
 needle:=' INSERT INTO zasp_temporal77.source_events(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime source insertion anchor changed';END IF;
 EXECUTE replace(d,needle,$new$ IF k='runtime_decision' THEN
  PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime source organization unavailable';END IF;
 END IF;
$new$||needle);
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal75.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 needle:='FUNCTION zasp_temporal75.admit_body(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime private admission header changed';END IF;
 d:=replace(d,needle,'FUNCTION zasp_authorization80_worker.runtime_admit_body(');
 needle:='public.zasp_production_security_agent_existing_tests_trigger(o,w,e,k,t,';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>4 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime private admission trigger calls changed';END IF;
 EXECUTE replace(d,needle,'zasp_authorization80_worker.runtime_trigger(o,w,e,d,v,r,k,t,');

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)';
 needle:=$old$ IF def.body->'allowed_actions' IS DISTINCT FROM '["update_finding_response"]'::jsonb THEN RETURN zasp_temporal75.admit_body(o,w,e,d,v,k,t,tv,r,actor_value,audit_value,correlation_value,automatic_value);END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime admission dispatch changed';END IF;
 replacement:=$new$ IF k='runtime_decision' AND def.body->'trigger_rules'->>'mode'='automatic' AND def.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb) THEN
 IF automatic_value IS DISTINCT FROM true THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime automatic provenance required';END IF;
 RETURN zasp_authorization80_worker.runtime_admit_body(o,w,e,d,v,k,t,tv,r,actor_value,audit_value,correlation_value,automatic_value);END IF;
$new$||needle;
 EXECUTE replace(d,needle,replacement);

 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal78.admit_occurrence(jsonb)';
 needle:=E'BEGIN\n';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime occurrence entry changed';END IF;
 d:=replace(d,needle,needle||E' PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;\n IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE=''42501'',MESSAGE=''runtime organization unavailable'';END IF;\n');
 needle:=$old$ ELSE RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime automatic adapter unavailable';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime occurrence source branch changed';END IF;
 EXECUTE replace(d,needle,$new$ ELSE PERFORM zasp_authorization80_worker.runtime_occurrence_match(o,w,e,id_value,def.body);END IF;$new$);

 FOR p IN SELECT * FROM zasp_authorization80_worker.predecessor_functions WHERE signature IN('zasp_temporal74.takeover(text,text,text,text)','zasp_temporal74.context(text,text,text,text)','zasp_temporal74.context_parent(text,text,text,text,jsonb)') LOOP
  d:=p.definition;
  IF p.signature='zasp_temporal74.takeover(text,text,text,text)' THEN
   needle:=$old$ PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||o,0));$old$;
   IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime takeover lock anchor changed';END IF;
   d:=replace(d,needle,$new$ PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=o FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime takeover organization unavailable';END IF;
$new$||needle);
  END IF;
  needle:='public.zasp_production_security_agent_existing_tests_trigger(o,w,e,t.trigger_kind,t.trigger_id,';
  -- Effective76 retains the automatic73 call and adds resource65. Both exact
  -- branches need the protocol-aware reader; nonconfigured sources delegate
  -- to the unchanged retained trigger validator inside runtime_trigger.
  IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime owned trigger reader changed';END IF;
  EXECUTE replace(d,needle,'zasp_authorization80_worker.runtime_trigger(o,w,e,rr.definition_id,rr.definition_version,r,t.trigger_kind,t.trigger_id,');
 END LOOP;
 SELECT definition INTO STRICT d FROM zasp_authorization80_worker.predecessor_functions WHERE signature='zasp_temporal77.rules_capable(jsonb)';
 needle:=$old$b->'trigger_rules'->>'mode'='manual' OR b->>'trigger_kind'='finding'$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime capability predicate changed';END IF;
 EXECUTE replace(d,needle,needle||$new$ OR b->>'trigger_kind'='runtime_decision' AND b->'trigger_rules'->>'mode'='automatic' AND zasp_temporal77.rules_valid(b)$new$);
END $runtime_admission$;
