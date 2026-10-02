-- Immutable runtime ancestry carries identifiers and digests only. The source
-- protocol is selected from original native ownership, not from a request flag.
CREATE TABLE zasp_authorization80_worker.runtime_associations(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,
 body jsonb NOT NULL,digest text NOT NULL CHECK(digest~'^[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 CHECK(digest=encode(public.digest(convert_to(body::text,'UTF8'),'sha256'),'hex')));
ALTER TABLE zasp_authorization80_worker.runtime_associations OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_authorization80_worker.runtime_associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_authorization80_worker.runtime_associations FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_authorization80_worker.runtime_associations TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_authorization80_worker.runtime_associations FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable();
CREATE TRIGGER worker_revision AFTER INSERT ON zasp_authorization80_worker.runtime_associations FOR EACH ROW EXECUTE FUNCTION zasp_authorization79.capture('organization_id','organization_id,workspace_id,environment_id,run_id');

CREATE FUNCTION zasp_authorization80_worker.runtime_capture(o text,w text,e text,r text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $capture$
DECLARE a zasp_authorization80_worker.runtime_associations%ROWTYPE;BEGIN
 SELECT * INTO STRICT a FROM zasp_authorization80_worker.runtime_associations WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 IF a.digest IS DISTINCT FROM encode(digest(convert_to(a.body::text,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime captured ancestry changed';END IF;
 RETURN a.body||jsonb_build_object('runtime_digest',a.digest);
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime captured ancestry absent';
END $capture$;

-- Called under the organization lock, then native parent ownership validation.
-- UTC affects only this private metadata digest, never retained audit bodies.
CREATE FUNCTION zasp_authorization80_worker.runtime_source(o text,w text,e text,r text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET timezone='UTC' AS $runtime_source$
DECLARE x zasp_temporal74.run_owners%ROWTYPE;t public.zasp_security_agent_trigger_receipts%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;
 a zasp_temporal77.occurrences%ROWTYPE;summary public.zasp_runtime_session_summaries%ROWTYPE;agent public.zasp_inventory_entities%ROWTYPE;
 event_value public.zasp_runtime_gateway_events%ROWTYPE;credential public.zasp_gateway_credentials%ROWTYPE;device public.zasp_gateway_devices%ROWTYPE;
 protocol text;session_value text;agent_value text;ids text[];device_ids text[];item text;native_value jsonb;matched jsonb;events_value jsonb:='[]'::jsonb;body_value jsonb;
 expiry timestamptz;window_seconds integer;event_digest text;credential_digest text;device_digest text;
BEGIN
 IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime ancestry unavailable';END IF;
 SELECT * INTO STRICT x FROM zasp_temporal74.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r);
 SELECT * INTO STRICT t FROM public.zasp_security_agent_trigger_receipts WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r) FOR SHARE;
 SELECT * INTO STRICT h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,x.definition_id,x.definition_version) FOR SHARE;
 IF t.trigger_kind<>'runtime_decision' OR(x.trigger_id,x.trigger_version,x.input_digest) IS DISTINCT FROM(t.trigger_id,t.trigger_version,encode(t.trigger_digest,'hex'))
 OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime original ownership changed';END IF;
 native_value:=zasp_authorization80_worker.runtime_trigger(o,w,e,x.definition_id,x.definition_version,r,t.trigger_kind,t.trigger_id,h.definition->>'trigger_source',t.trigger_version);
 IF native_value->>'digest' IS DISTINCT FROM x.input_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime trigger proof changed';END IF;
 IF h.definition->'trigger_rules'->>'mode'='automatic' THEN
  protocol:='configured77-event-occurrence';
  SELECT * INTO STRICT a FROM zasp_temporal77.occurrences WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version,run_id,disposition)=(o,w,e,x.definition_id,x.definition_version,r,'admitted') FOR SHARE;
  matched:=zasp_authorization80_worker.runtime_occurrence_match(o,w,e,a.event_id,h.definition);
  IF matched IS NULL OR matched->'evidence' IS DISTINCT FROM a.snapshot OR decode(matched->>'digest','hex') IS DISTINCT FROM a.snapshot_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime occurrence ancestry changed';END IF;
  session_value:=a.snapshot#>>'{anchor,evaluation,session_id}';agent_value:=a.snapshot#>>'{anchor,evaluation,agent_id}';
  window_seconds:=(h.definition#>>'{trigger_rules,runtime,window_seconds}')::integer;
  SELECT array_agg(id ORDER BY id) INTO ids FROM(SELECT DISTINCT value->>'event_id' id FROM jsonb_array_elements(a.snapshot->'events') UNION SELECT a.snapshot#>>'{anchor,event_id}') selected;
  IF cardinality(ids) NOT BETWEEN 1 AND 101 OR EXISTS(SELECT 1 FROM jsonb_array_elements(a.snapshot->'events') v WHERE(v#>>'{evaluation,session_id}',v#>>'{evaluation,agent_id}') IS DISTINCT FROM(session_value,agent_value)) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime configured ancestry ambiguous';END IF;
 ELSE
  protocol:='retained74-session-latest';session_value:=t.trigger_id;window_seconds:=300;
  SELECT event.* INTO STRICT event_value FROM public.zasp_runtime_gateway_events event
  WHERE(event.organization_id,event.workspace_id,event.environment_id,event.classification->>'session_id',event.decision,event.classification->>'outcome')=(o,w,e,t.trigger_id,'block',h.definition->>'trigger_source')
   AND event.occurred_at<=clock_timestamp() ORDER BY event.occurred_at DESC,event.sequence DESC,event.event_id DESC LIMIT 1 FOR SHARE;
  IF event_value.sequence<>t.trigger_version OR encode(digest(convert_to(jsonb_build_object('kind','runtime_decision','session_id',t.trigger_id,'device_id',event_value.device_id,'event_id',event_value.event_id,'sequence',event_value.sequence,'request_digest','sha256:'||encode(event_value.request_digest,'hex'))::text,'UTF8'),'sha256'),'hex') IS DISTINCT FROM x.input_digest THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime retained ancestry changed';END IF;
  ids:=ARRAY[event_value.event_id];
 END IF;
 SELECT * INTO STRICT summary FROM public.zasp_runtime_session_summaries WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,session_value) FOR SHARE;
 IF summary.id='unattributed' OR summary.minimum_agent_id IS NULL OR summary.minimum_agent_id IS DISTINCT FROM summary.maximum_agent_id
 OR summary.probable_count<>0 OR summary.unattributed_count<>0 OR agent_value IS NOT NULL AND agent_value IS DISTINCT FROM summary.minimum_agent_id THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime session attribution unavailable';END IF;
 agent_value:=summary.minimum_agent_id;
 SELECT * INTO STRICT agent FROM public.zasp_inventory_entities WHERE(organization_id,workspace_id,environment_id,id,product_kind,state)=(o,w,e,agent_value,'agent','active') FOR SHARE;
 IF agent.fresh_until IS NULL OR agent.fresh_until<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime source agent expired';END IF;
 expiry:=agent.fresh_until;
 -- Identity ordering is deterministic. All supported source writers acquire
 -- the organization lock before their first device or source-row lock.
 PERFORM 1 FROM public.zasp_gateway_devices d WHERE(d.organization_id,d.workspace_id,d.environment_id)=(o,w,e) AND d.id IN(SELECT v.device_id FROM public.zasp_runtime_gateway_events v WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e) AND v.event_id=ANY(ids)) ORDER BY d.id FOR SHARE;
 PERFORM 1 FROM public.zasp_gateway_credentials c WHERE(c.organization_id,c.workspace_id,c.environment_id)=(o,w,e) AND c.id IN(SELECT v.credential_id FROM public.zasp_runtime_gateway_events v WHERE(v.organization_id,v.workspace_id,v.environment_id)=(o,w,e) AND v.event_id=ANY(ids)) ORDER BY c.device_id,c.id FOR SHARE;
 FOREACH item IN ARRAY ids LOOP
  SELECT * INTO STRICT event_value FROM public.zasp_runtime_gateway_events WHERE(organization_id,workspace_id,environment_id,event_id)=(o,w,e,item) FOR SHARE;
  SELECT * INTO STRICT device FROM public.zasp_gateway_devices WHERE(organization_id,workspace_id,environment_id,id)=(o,w,e,event_value.device_id);
  SELECT * INTO STRICT credential FROM public.zasp_gateway_credentials WHERE(organization_id,workspace_id,environment_id,device_id,id)=(o,w,e,event_value.device_id,event_value.credential_id);
  IF device.state<>'active' OR credential.revoked_at IS NOT NULL OR credential.expires_at<=clock_timestamp() OR event_value.occurred_at>clock_timestamp()
   OR event_value.occurred_at+make_interval(secs=>window_seconds)<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime source authority expired';END IF;
  -- Full event and credential bodies are hashed privately; no endpoint, key
  -- reference, classification or evaluation body leaves this metadata reader.
  event_digest:=encode(digest(convert_to(to_jsonb(event_value)::text,'UTF8'),'sha256'),'hex');
  credential_digest:=encode(digest(convert_to(to_jsonb(credential)::text,'UTF8'),'sha256'),'hex');
  device_digest:=encode(digest(convert_to(jsonb_build_array(o,w,e,device.id,device.state,device.revoked_at)::text,'UTF8'),'sha256'),'hex');
  events_value:=events_value||jsonb_build_array(jsonb_build_object('event_id',item,'sequence',event_value.sequence,'event_digest',event_digest,'device_id',device.id,'device_digest',device_digest,'credential_id',credential.id,'credential_digest',credential_digest));
  device_ids:=array_append(device_ids,device.id);
  expiry:=least(expiry,credential.expires_at,event_value.occurred_at+make_interval(secs=>window_seconds));
 END LOOP;
 SELECT array_agg(id ORDER BY id) INTO device_ids FROM(SELECT DISTINCT unnest(device_ids) id) d;
 IF cardinality(device_ids) NOT BETWEEN 1 AND 101 THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime source device count rejected';END IF;
 IF zasp_authorization80_worker.runtime_trigger(o,w,e,x.definition_id,x.definition_version,r,t.trigger_kind,t.trigger_id,h.definition->>'trigger_source',t.trigger_version) IS DISTINCT FROM native_value
 OR expiry<=clock_timestamp() OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime ancestry changed after locks';END IF;
 body_value:=jsonb_build_object('runtime_protocol',protocol,'source_session_id',session_value,'source_agent_id',agent_value,'source_device_ids',to_jsonb(device_ids),
 'match',CASE WHEN protocol='configured77-event-occurrence' THEN h.definition#>'{trigger_rules,runtime}' ELSE jsonb_build_object('outcome',h.definition->>'trigger_source') END,
 'definition_digest',encode(h.definition_digest,'hex'),'trigger_digest',x.input_digest,'source_events',events_value,
 'session_digest',encode(digest(convert_to(to_jsonb(summary)::text,'UTF8'),'sha256'),'hex'),'source_agent_digest',encode(digest(convert_to(to_jsonb(agent)::text,'UTF8'),'sha256'),'hex'),
 'fresh_until_ms',floor(extract(epoch FROM expiry)*1000)::bigint);
 RETURN body_value||jsonb_build_object('runtime_digest',encode(digest(convert_to(body_value::text,'UTF8'),'sha256'),'hex'));
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime source ancestry unavailable';
END $runtime_source$;

-- These fixed copies are owner-only. The source keeps its complete exit fence;
-- only its facts caller can supply the unchanged same-call entry fence.
DO $runtime_inner_readers$ DECLARE d text;needle text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.runtime_occurrence_match(text,text,text,text,jsonb)'::regprocedure);
 needle:='runtime_occurrence_match(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner matcher declaration changed';END IF;
 d:=replace(d,needle,'runtime_occurrence_match_inner(');
 needle:=$old$IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready()
 OR b->>'trigger_kind'$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner matcher entry changed';END IF;
 d:=replace(d,needle,$new$IF b->>'trigger_kind'$new$);
 needle:=$old$  IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime occurrence catalog changed';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner matcher empty exit changed';END IF;
 d:=replace(d,needle,'');
 needle:=$old$IF after_value IS DISTINCT FROM before_value OR NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready()$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner matcher exit changed';END IF;
 EXECUTE replace(d,needle,'IF after_value IS DISTINCT FROM before_value');

 d:=pg_get_functiondef('zasp_authorization80_worker.runtime_trigger(text,text,text,text,bigint,text,text,text,text,bigint)'::regprocedure);
 needle:='runtime_trigger(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner trigger declaration changed';END IF;
 d:=replace(d,needle,'runtime_trigger_inner(');
 needle:='zasp_authorization80_worker.runtime_occurrence_match(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inner trigger matcher changed';END IF;
 EXECUTE replace(d,needle,'zasp_authorization80_worker.runtime_occurrence_match_inner(');

 d:=pg_get_functiondef('zasp_authorization80_worker.runtime_source(text,text,text,text)'::regprocedure);
 needle:='zasp_authorization80_worker.runtime_trigger(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime source trigger pair changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.runtime_trigger_inner(');
 needle:='zasp_authorization80_worker.runtime_occurrence_match(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime source matcher changed';END IF;
 d:=replace(d,needle,'zasp_authorization80_worker.runtime_occurrence_match_inner(');
 EXECUTE d;
 needle:='runtime_source(';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime after-entry declaration changed';END IF;
 d:=replace(d,needle,'runtime_source_after_entry(');
 needle:=$old$ IF NOT zasp_authorization80_worker.catalog_ready() OR NOT zasp_temporal74.current_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime ancestry unavailable';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime after-entry fence changed';END IF;
 EXECUTE replace(d,needle,'');
END $runtime_inner_readers$;

CREATE FUNCTION zasp_authorization80_worker.runtime_public_facts(f jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $public_facts$
 SELECT jsonb_build_object('runtime_protocol',f->'runtime_protocol','runtime_digest',f->'runtime_digest','source_session_id',f->'source_session_id','source_agent_id',f->'source_agent_id','source_device_ids',f->'source_device_ids')
$public_facts$;

DO $runtime_test_sources$ DECLARE d text;needle text;replacement text;BEGIN
 d:=pg_get_functiondef('zasp_authorization80_worker.test74_private_facts(boolean,jsonb,boolean,jsonb)'::regprocedure);
 needle:=$old$IF compensation IS NULL OR execution IS NULL OR NOT zasp_temporal74.current_ready() OR NOT zasp_authorization80_worker.catalog_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test source reader rejected';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enclosing facts entry changed';END IF;
 needle:='metadata jsonb;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime test metadata declaration changed';END IF;
 d:=replace(d,needle,'metadata jsonb;runtime_value jsonb;');
 needle:=' x:=zasp_temporal74.start_identity(q);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime test identity entry changed';END IF;
 d:=replace(d,needle,$lock$ IF NOT compensation THEN
  PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=q->>'organization_id' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime test organization unavailable';END IF;
 END IF;
$lock$||needle);
 needle:=' IF compensation THEN';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime compensation branch changed';END IF;
 d:=replace(d,needle,needle||$capture$
  IF a.trigger_kind='runtime_decision' THEN
   runtime_value:=zasp_authorization80_worker.runtime_capture(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   source_hash:=encode(digest(convert_to(jsonb_build_array(source_hash,runtime_value->>'runtime_digest')::text,'UTF8'),'sha256'),'hex');
  END IF;
$capture$);
 needle:=$old$metadata:=to_jsonb(a);checks:='[]'::jsonb;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime captured metadata changed';END IF;
 d:=replace(d,needle,needle||$new$IF runtime_value IS NOT NULL THEN metadata:=metadata||zasp_authorization80_worker.runtime_public_facts(runtime_value);END IF;$new$);
 needle:=$old$IF trigger_value='runtime_decision' THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='worker test trigger unsupported';END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime unsupported source anchor changed';END IF;
 d:=replace(d,needle,$new$IF trigger_value='runtime_decision' THEN
   runtime_value:=zasp_authorization80_worker.runtime_source_after_entry(x.organization_id,x.workspace_id,x.environment_id,x.run_id);
   source_hash:=encode(digest(convert_to(jsonb_build_array(source_hash,runtime_value->>'runtime_digest')::text,'UTF8'),'sha256'),'hex');
   expires:=least(expires,to_timestamp((runtime_value->>'fresh_until_ms')::numeric/1000));
  END IF;$new$);
 needle:=$old$  ELSIF trigger_value IN('finding','attack_path') THEN checks:=checks||jsonb_build_array(jsonb_build_object('kind',trigger_value,'id',x.trigger_id,'permission','view'));END IF;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime source check extension changed';END IF;
 d:=replace(d,needle,needle||$new$
  IF runtime_value IS NOT NULL THEN
   metadata:=metadata||zasp_authorization80_worker.runtime_public_facts(runtime_value);
   checks:=checks||jsonb_build_array(jsonb_build_object('kind','session','id',runtime_value->>'source_session_id','permission','investigate_sessions'),jsonb_build_object('kind','agent','id',runtime_value->>'source_agent_id','permission','view'));
   checks:=checks||(SELECT jsonb_agg(jsonb_build_object('kind','gateway_device','id',id,'permission','view') ORDER BY id) FROM jsonb_array_elements_text(runtime_value->'source_device_ids') id);
  END IF;
$new$);
 EXECUTE d;

 d:=pg_get_functiondef('zasp_authorization80_worker.prepare_test74(jsonb)'::regprocedure);
 needle:='DECLARE f jsonb;';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime preparation declaration changed';END IF;
 d:=replace(d,needle,'DECLARE runtime_value jsonb;f jsonb;');
 needle:=' a:=jsonb_populate_record(NULL::zasp_authorization80_worker.test_associations,f);';
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime preparation capture changed';END IF;
 d:=replace(d,needle,needle||$new$
 IF f->>'trigger_kind'='runtime_decision' THEN
  runtime_value:=zasp_authorization80_worker.runtime_source(a.organization_id,a.workspace_id,a.environment_id,a.run_id);
  IF runtime_value->>'runtime_digest' IS DISTINCT FROM f->>'runtime_digest' THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime preparation source changed';END IF;
  INSERT INTO zasp_authorization80_worker.runtime_associations VALUES(a.organization_id,a.workspace_id,a.environment_id,a.run_id,runtime_value-'runtime_digest',runtime_value->>'runtime_digest') ON CONFLICT DO NOTHING;
  IF zasp_authorization80_worker.runtime_capture(a.organization_id,a.workspace_id,a.environment_id,a.run_id) IS DISTINCT FROM runtime_value THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='runtime preparation capture differs';END IF;
 END IF;
$new$);
 EXECUTE d;

 d:=pg_get_functiondef('zasp_authorization80_worker.adapter74_source(text,jsonb)'::regprocedure);
 needle:=$old$ PERFORM pg_advisory_xact_lock(hashtextextended('security-agent-budget-admission:'||x.organization_id,0));$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime adapter lock anchor changed';END IF;
 EXECUTE replace(d,needle,$new$ PERFORM 1 FROM zasp_authorization79.organizations WHERE organization_id=x.organization_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime adapter organization unavailable';END IF;
$new$||needle);
END $runtime_test_sources$;

-- These triggers invalidate existing captures only. Creation of authority is
-- restricted to prepare_test74 after native context validation under org lock.
CREATE FUNCTION zasp_authorization80_worker.capture_runtime_source() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $runtime_invalidate$
DECLARE old_value jsonb:=to_jsonb(OLD);new_value jsonb:=to_jsonb(NEW);v jsonb;scope_value text;relation_value text:=TG_TABLE_NAME;BEGIN
 IF TG_TABLE_SCHEMA='zasp_temporal77' AND TG_TABLE_NAME='source_events' THEN
  IF TG_OP<>'INSERT' OR NEW.source_kind<>'runtime_decision' THEN RETURN NEW;END IF;
  -- Catch-up can add a reference to an already committed evaluation. The
  -- ordinary event writer inserts that evaluation later in its transaction.
  SELECT to_jsonb(a) INTO new_value FROM zasp_temporal77.runtime_evaluations a
  WHERE(a.organization_id,a.workspace_id,a.environment_id,a.event_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.source_id);
  IF new_value IS NULL THEN RETURN NEW;END IF;
  old_value:=NULL;relation_value:='runtime_evaluations';
 END IF;
 IF TG_OP='UPDATE' AND old_value IS NOT DISTINCT FROM new_value THEN RETURN NEW;END IF;
 IF TG_TABLE_NAME='zasp_gateway_devices' AND TG_OP='UPDATE' AND
  (old_value->'organization_id',old_value->'workspace_id',old_value->'environment_id',old_value->'id',old_value->'state',old_value->'revoked_at') IS NOT DISTINCT FROM
  (new_value->'organization_id',new_value->'workspace_id',new_value->'environment_id',new_value->'id',new_value->'state',new_value->'revoked_at') THEN RETURN NEW;END IF;
 FOR v IN SELECT x FROM unnest(ARRAY[old_value,new_value]) x WHERE x IS NOT NULL LOOP
  UPDATE zasp_authorization80_worker.test_state s SET target_current=false
  FROM zasp_authorization80_worker.runtime_associations a
  WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND s.target_current
  AND(a.organization_id,a.workspace_id,a.environment_id)=(v->>'organization_id',v->>'workspace_id',v->>'environment_id')
  AND CASE relation_value
   WHEN 'zasp_gateway_devices' THEN a.body->'source_device_ids' ? (v->>'id')
   WHEN 'zasp_gateway_credentials' THEN a.body->'source_device_ids' ? (v->>'device_id')
   WHEN 'zasp_runtime_session_summaries' THEN a.body->>'source_session_id'=v->>'id'
   WHEN 'zasp_runtime_gateway_events' THEN
    EXISTS(SELECT 1 FROM jsonb_array_elements(a.body->'source_events') event WHERE event->>'event_id'=v->>'event_id')
    OR a.body->>'runtime_protocol'='retained74-session-latest' AND v->'classification'->>'session_id'=a.body->>'source_session_id'
     AND v->>'decision'='block' AND v->'classification'->>'outcome'=a.body->'match'->>'outcome'
   WHEN 'runtime_evaluations' THEN
    EXISTS(SELECT 1 FROM jsonb_array_elements(a.body->'source_events') event WHERE event->>'event_id'=v->>'event_id')
    OR a.body->>'runtime_protocol'='configured77-event-occurrence'
     AND (v->'evaluation'->>'session_id',v->'evaluation'->>'agent_id',v->'evaluation'->>'action')=(a.body->>'source_session_id',a.body->>'source_agent_id',a.body->'match'->>'action')
     AND (NOT a.body->'match'?'risk' OR v->'evaluation'->>'risk'=a.body->'match'->>'risk')
     AND EXISTS(SELECT 1 FROM public.zasp_runtime_gateway_events event WHERE(event.organization_id,event.workspace_id,event.environment_id,event.event_id,event.decision)=(a.organization_id,a.workspace_id,a.environment_id,v->>'event_id',a.body->'match'->>'decision')
      AND event.occurred_at BETWEEN clock_timestamp()-make_interval(secs=>(a.body->'match'->>'window_seconds')::integer) AND clock_timestamp())
   ELSE false END;
 END LOOP;
 -- Resource existence/state is separate from whether any task captured it.
 IF TG_TABLE_NAME='zasp_gateway_devices' THEN
  FOR scope_value IN SELECT DISTINCT id FROM unnest(ARRAY[old_value->>'organization_id',new_value->>'organization_id']) id WHERE id IS NOT NULL ORDER BY id LOOP
   PERFORM zasp_authorization79.touch(scope_value);
  END LOOP;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $runtime_invalidate$;

DO $runtime_triggers$ DECLARE target text;d text;needle text;BEGIN
 FOREACH target IN ARRAY ARRAY['public.zasp_gateway_devices','public.zasp_gateway_credentials','public.zasp_runtime_session_summaries','public.zasp_runtime_gateway_events','zasp_temporal77.runtime_evaluations','zasp_temporal77.source_events'] LOOP
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_runtime_capture AFTER INSERT OR UPDATE OR DELETE ON %s FOR EACH ROW EXECUTE FUNCTION zasp_authorization80_worker.capture_runtime_source()',target);
  EXECUTE format('CREATE TRIGGER zasp_authorization80_worker_runtime_no_truncate BEFORE TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',target);
 END LOOP;
 -- Reuse the existing independently pinned inventory trigger. Its original
 -- target selection remains, with an extra branch for captured source agents.
 d:=pg_get_functiondef('zasp_authorization80_worker.capture_test_target()'::regprocedure);
 needle:=$old$ IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;$old$;
 IF(length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime inventory capture return changed';END IF;
 EXECUTE replace(d,needle,$new$ IF TG_TABLE_NAME='zasp_inventory_entities' THEN
  UPDATE zasp_authorization80_worker.test_state s SET target_current=false FROM zasp_authorization80_worker.runtime_associations a
  WHERE(s.organization_id,s.workspace_id,s.environment_id,s.run_id)=(a.organization_id,a.workspace_id,a.environment_id,a.run_id) AND s.target_current
  AND(a.organization_id,a.workspace_id,a.environment_id,a.body->>'source_agent_id')=(old_value->>'organization_id',old_value->>'workspace_id',old_value->>'environment_id',old_value->>'id');
 END IF;
$new$||needle);
END $runtime_triggers$;

DO $runtime_grants$ DECLARE d text;BEGIN
 SELECT pg_get_viewdef('zasp_authorization79.current_grants'::regclass) INTO STRICT d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.current_grants AS '||rtrim(d,E';\n ')||$grant$
 UNION SELECT a.organization_id,a.workspace_id,a.environment_id,target.kind,target.id,'service'::text,a.principal_id,target.permission,a.run_id
 FROM zasp_authorization80_worker.active_tests a JOIN zasp_authorization80_worker.runtime_associations r USING(organization_id,workspace_id,environment_id,run_id)
 CROSS JOIN LATERAL(SELECT 'session'::text kind,r.body->>'source_session_id' id,'investigate_sessions'::text permission
  UNION ALL SELECT 'agent',r.body->>'source_agent_id','view'
  UNION ALL SELECT 'gateway_device',id,'view' FROM jsonb_array_elements_text(r.body->'source_device_ids') id) target
 WHERE a.trigger_kind='runtime_decision'$grant$;
 -- Gateway writer closure is installed before this module. Never publish the
 -- union separately from source capture, invalidation and org-first writers.
 SELECT pg_get_viewdef('zasp_authorization79.resources'::regclass) INTO STRICT d;
 EXECUTE 'CREATE OR REPLACE VIEW zasp_authorization79.resources AS '||rtrim(d,E';\n ')||$resource$
 UNION SELECT organization_id,workspace_id,environment_id,'gateway_device'::text,id FROM public.zasp_gateway_devices$resource$;
END $runtime_grants$;
