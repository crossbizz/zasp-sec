-- Omission keeps the historical finding predicate, not a persisted rule rewrite.
CREATE FUNCTION zasp_temporal78.automatic_body(b jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $automatic$
 SELECT COALESCE(CASE WHEN b?'trigger_rules' THEN b->'trigger_rules'->>'mode'='automatic' ELSE zasp_temporal78.capable(b) END,false)
$automatic$;
CREATE FUNCTION zasp_temporal78.source_match(o text,w text,e text,event_value text,b jsonb,at_value timestamptz) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public SET timezone TO 'UTC' AS $match$
DECLARE s zasp_temporal77.source_events%ROWTYPE;f public.zasp_risk_findings%ROWTYPE;evidence_value jsonb;identity_value jsonb;BEGIN
 IF b?'trigger_rules' OR NOT zasp_temporal78.capable(b) THEN RETURN zasp_temporal77.source_match(o,w,e,event_value,b,at_value);END IF;
 SELECT * INTO s FROM zasp_temporal77.source_events WHERE(organization_id,workspace_id,environment_id,event_id,source_kind)=(o,w,e,event_value,'finding');
 IF NOT FOUND OR at_value IS NULL OR NOT COALESCE(b->'environment_ids'?e,false) THEN RETURN NULL;END IF;
 SELECT * INTO f FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id,version)=(o,w,e,s.source_id,s.source_version);
 IF NOT FOUND OR f.status<>'open' OR COALESCE(f.rule,f.source) IS DISTINCT FROM b->>'trigger_source' OR NOT public.zasp_risk_finding_visible(f) THEN RETURN NULL;END IF;
 identity_value:=jsonb_build_object('kind','finding','id',f.id,'version',f.version);
 evidence_value:=jsonb_build_object('kind','finding','source',to_jsonb(f),
  'evidence',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_evidence child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,f.id)),
  'factors',(SELECT COALESCE(jsonb_agg(to_jsonb(child) ORDER BY position),'[]'::jsonb) FROM public.zasp_risk_finding_factors child WHERE(organization_id,workspace_id,environment_id,finding_id)=(o,w,e,f.id)));
 RETURN jsonb_build_object('event_id',s.event_id,'kind','finding','trigger_id',f.id,'version',f.version,
  'digest',encode(digest(convert_to(evidence_value::text,'UTF8'),'sha256'),'hex'),'evidence',evidence_value,
  'cooldown_key',encode(digest(convert_to(jsonb_build_array('finding',f.id)::text,'UTF8'),'sha256'),'hex'),
  'legacy_trigger_digest',encode(digest(convert_to(identity_value::text,'UTF8'),'sha256'),'hex'));
END $match$;

DO $admission$ DECLARE d text;needle text;BEGIN
 SELECT pg_get_functiondef('zasp_temporal78.admit_occurrence(jsonb)'::regprocedure) INTO d;
 needle:=$old$def.body->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic'$old$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted admission predecessor changed';END IF;
 d:=replace(d,needle,'NOT zasp_temporal78.automatic_body(def.body)');
 IF (length(d)-length(replace(d,'zasp_temporal77.source_match(','')))/length('zasp_temporal77.source_match(')<>2 THEN RAISE EXCEPTION 'finding omitted matcher predecessor changed';END IF;
 d:=replace(d,'zasp_temporal77.source_match(','zasp_temporal78.source_match(');
 needle:='  INSERT INTO zasp_temporal77.cooldowns VALUES';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted cooldown predecessor changed';END IF;
 d:=replace(d,needle,$new$  IF def.body?'trigger_rules' THEN
  INSERT INTO zasp_temporal77.cooldowns VALUES$new$);
 needle:='DO UPDATE SET admitted_at=EXCLUDED.admitted_at,admitted_until=EXCLUDED.admitted_until;';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted cooldown end changed';END IF;
 EXECUTE replace(d,needle,needle||' END IF;');
 SELECT pg_get_functiondef('zasp_temporal78.admit_body(text,text,text,text,bigint,text,text,bigint,text,text,text,text,boolean)'::regprocedure) INTO d;
 needle:=$old$rule=def.body->>'trigger_source'$old$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted source family changed';END IF;
 EXECUTE replace(d,needle,$new$(CASE WHEN def.body?'trigger_rules' THEN rule ELSE COALESCE(rule,source) END)=def.body->>'trigger_source'$new$);
END $admission$;

CREATE OR REPLACE FUNCTION zasp_temporal78.desired(q jsonb) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $desired$
DECLARE result_value jsonb;b jsonb;BEGIN
 PERFORM zasp_temporal77.require_executor();
 result_value:=zasp_temporal78.desired_base(q);
 SELECT body INTO b FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id)=(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id');
 IF b->'allowed_actions'='["update_finding_response"]'::jsonb THEN
  result_value:=result_value||jsonb_build_object('automatic',true,'enabled',(result_value->>'enabled')::boolean AND zasp_temporal78.automatic_body(b) AND zasp_temporal78.capable(b) AND zasp_temporal78.definition_migrated(q->>'organization_id',q->>'workspace_id',q->>'environment_id',q->>'definition_id'));
 ELSIF b?'trigger_rules' THEN
  result_value:=result_value||jsonb_build_object('automatic',true,'enabled',(result_value->>'enabled')::boolean AND b->'trigger_rules'->>'mode'='automatic' AND zasp_temporal77.rules_valid(b) AND zasp_temporal77.rules_capable(b));
 END IF;
 RETURN result_value;
END $desired$;

INSERT INTO zasp_temporal78.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN('zasp_temporal77.dispatch_page(jsonb)'::regprocedure,'zasp_temporal77.catchup_definition(jsonb)'::regprocedure);
DO $pages$ DECLARE p record;d text;needle text;BEGIN
 FOR p IN SELECT * FROM zasp_temporal78.predecessor_functions WHERE signature IN('zasp_temporal77.dispatch_page(jsonb)','zasp_temporal77.catchup_definition(jsonb)') LOOP
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION 'finding omitted page owner changed';END IF;
  d:=replace(p.definition,'FUNCTION zasp_temporal77.','FUNCTION zasp_temporal78.');
  IF p.signature='zasp_temporal77.dispatch_page(jsonb)' THEN
   needle:=$old$AND body ? 'trigger_rules' AND$old$;
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted page candidate changed';END IF;
   d:=replace(d,needle,$new$AND (body ? 'trigger_rules' OR zasp_temporal78.capable(body) AND zasp_temporal78.definition_migrated(o,w,e,definition_id)) AND$new$);
  ELSE
   needle:=$old$def.body->'trigger_rules'->>'mode' IS DISTINCT FROM 'automatic'$old$;
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding omitted catch-up mode changed';END IF;
   d:=replace(d,needle,'NOT zasp_temporal78.automatic_body(def.body)');
  END IF;
  EXECUTE d;
 END LOOP;
END $pages$;
CREATE OR REPLACE FUNCTION zasp_temporal77.dispatch_page(q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$ SELECT zasp_temporal78.dispatch_page(q) $page$;
CREATE OR REPLACE FUNCTION zasp_temporal77.catchup_definition(q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $page$ SELECT zasp_temporal78.catchup_definition(q) $page$;
