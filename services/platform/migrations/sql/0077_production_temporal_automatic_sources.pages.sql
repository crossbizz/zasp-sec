-- Temporal carries this cursor. A page counts visited definitions, not only
-- successful admissions, and never marks the source globally consumed.
-- Five is the measured work quantum under the25s Activity database budget;
-- it is below the25-visited upper bound and retains every authority check.
CREATE FUNCTION zasp_temporal77.dispatch_page(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
DECLARE o text:=q->>'organization_id';w text:=q->>'workspace_id';e text:=q->>'environment_id';event_value text:=q->>'event_id';after_value text:=q->>'after';
 source_value zasp_temporal77.source_events%ROWTYPE;configuration_value zasp_temporal75.configuration%ROWTYPE;item record;result_value jsonb;
 scanned_value integer:=0;admitted_value integer:=0;retry_value boolean:=false;
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF NOT COALESCE(zasp_sa_multistep_prior.closed(q,ARRAY['organization_id','workspace_id','environment_id','event_id','after'])
 AND public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(event_value)
 AND jsonb_typeof(q->'after')='string' AND (after_value='' OR public.zasp_valid_product_id(after_value)),false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic definition page rejected';END IF;
 SELECT * INTO source_value FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,event_value);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic page source scope denied';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('test-selector75-configuration',0));
 SELECT * INTO configuration_value FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND OR NOT configuration_value.enabled THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='automatic dispatcher paused';END IF;
 FOR item IN SELECT definition_id FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id)=(o,w,e)
  AND definition_id>after_value AND body ? 'trigger_rules' AND body->>'trigger_kind'=source_value.source_kind ORDER BY definition_id LIMIT 5 LOOP
  scanned_value:=scanned_value+1;after_value:=item.definition_id;
  BEGIN
   result_value:=zasp_temporal77.admit_occurrence(jsonb_build_object('ref',jsonb_build_object('organization_id',o,'workspace_id',w,'environment_id',e,'definition_id',item.definition_id),'revision',configuration_value.revision,'event_id',event_value));
   IF result_value->>'disposition'='admitted' THEN admitted_value:=admitted_value+1;END IF;
  EXCEPTION
   WHEN SQLSTATE '40001' OR SQLSTATE '55P03' THEN retry_value:=true;
   -- Current grant/definition revocation fails closed without consuming an
   -- occurrence. Later activation is handled by current-source catch-up.
   WHEN SQLSTATE '42501' THEN NULL;
  END;
 END LOOP;
 RETURN jsonb_build_object('after',after_value,'more',scanned_value=5,'retry',retry_value,'scanned',scanned_value,'admitted',admitted_value);
END $page$;

-- Current canonical source paging preserves preactivation catch-up. Inserting
-- an absent reference reuses source identity/version/time, never activation time.
CREATE FUNCTION zasp_temporal77.catchup_definition(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$
DECLARE ref jsonb:=q->'ref';o text:=ref->>'organization_id';w text:=ref->>'workspace_id';e text:=ref->>'environment_id';d text:=ref->>'definition_id';after_value text:=q->>'after';
 def public.zasp_security_agent_definitions%ROWTYPE;configuration_value zasp_temporal75.configuration%ROWTYPE;item record;result_value jsonb;table_value text;event_value text;
 scanned_value integer:=0;admitted_value integer:=0;retry_value boolean:=false;
BEGIN
 PERFORM zasp_temporal77.require_executor();
 IF NOT COALESCE(zasp_sa_multistep_prior.closed(q,ARRAY['ref','revision','after']) AND zasp_sa_multistep_prior.closed(ref,ARRAY['organization_id','workspace_id','environment_id','definition_id'])
 AND public.zasp_valid_product_id(o) AND public.zasp_valid_product_id(w) AND public.zasp_valid_product_id(e) AND public.zasp_valid_product_id(d)
 AND jsonb_typeof(q->'after')='string' AND (after_value='' OR public.zasp_valid_product_id(after_value))
 AND jsonb_typeof(q->'revision')='number' AND q->>'revision'~'^[1-9][0-9]{0,6}$' AND (q->>'revision')::bigint<=1000000,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='automatic catch-up page rejected';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('test-selector75-configuration',0));
 SELECT * INTO configuration_value FROM zasp_temporal75.configuration ORDER BY revision DESC LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='automatic catch-up configuration missing';END IF;
 SELECT * INTO def FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d);
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic catch-up definition scope denied';END IF;
 IF NOT configuration_value.enabled OR configuration_value.revision<>(q->>'revision')::bigint OR def.deleted_at IS NOT NULL OR def.activation NOT IN('supervised','autonomous')
 OR def.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR def.body->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic' THEN
  RETURN jsonb_build_object('after',after_value,'more',false,'retry',false,'scanned',0,'admitted',0);
 END IF;
 IF NOT zasp_temporal77.rules_valid(def.body) OR NOT zasp_temporal77.rules_capable(def.body) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic catch-up adapter unavailable';END IF;
 table_value:=CASE def.body->>'trigger_kind' WHEN 'finding' THEN 'zasp_risk_findings' WHEN 'attack_path' THEN 'zasp_risk_attack_paths' END;
 IF table_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='automatic catch-up source adapter unavailable';END IF;
 FOR item IN EXECUTE format('SELECT id,version,updated_at FROM public.%I WHERE(organization_id,workspace_id,environment_id)=($1,$2,$3) AND id>$4 ORDER BY id LIMIT 5',table_value) USING o,w,e,after_value LOOP
  scanned_value:=scanned_value+1;after_value:=item.id;
  PERFORM zasp_temporal77.put_source(o,w,e,def.body->>'trigger_kind',item.id,item.version,item.updated_at);
  event_value:=public.zasp_discovery_canonical_id(o,w,e,'automatic_source_v1',concat_ws(chr(31),def.body->>'trigger_kind',item.id,item.version));
  BEGIN
   result_value:=zasp_temporal77.admit_occurrence(jsonb_build_object('ref',ref,'revision',configuration_value.revision,'event_id',event_value));
   IF result_value->>'disposition'='admitted' THEN admitted_value:=admitted_value+1;END IF;
  EXCEPTION
   WHEN SQLSTATE '40001' OR SQLSTATE '55P03' THEN retry_value:=true;
   WHEN SQLSTATE '42501' THEN NULL;
  END;
 END LOOP;
 RETURN jsonb_build_object('after',after_value,'more',scanned_value=5,'retry',retry_value,'scanned',scanned_value,'admitted',admitted_value);
END $page$;
