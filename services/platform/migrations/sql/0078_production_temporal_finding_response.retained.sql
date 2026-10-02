-- Sticky routing is historical provenance, not current execution authority.
-- Edits/revocation cannot return a migrated definition to the legacy scheduler.
CREATE FUNCTION zasp_temporal78.definition_migrated(o text,w text,e text,d text) RETURNS boolean LANGUAGE plpgsql STABLE SET search_path TO pg_catalog,public AS $migrated$
DECLARE g zasp_temporal78.service_grants%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;a public.zasp_security_agent_audit%ROWTYPE;found_value boolean:=false;BEGIN
 FOR g IN SELECT * FROM zasp_temporal78.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id)=(o,w,e,d) LOOP
  SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,g.definition_version);
  SELECT * INTO a FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(o,w,e,g.audit_id);
  IF h.definition_id IS NULL OR NOT zasp_temporal78.capable(h.definition) OR h.activation NOT IN('supervised','autonomous') OR h.definition_digest IS DISTINCT FROM digest(convert_to(h.definition::text,'UTF8'),'sha256') OR h.definition_digest IS DISTINCT FROM g.definition_digest
   OR g.principal_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_definition_service',d)
   OR g.audit_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_finding_delegation',d||chr(31)||g.definition_version::text)
   OR a.actor_id IS DISTINCT FROM g.grantor_id OR a.event_kind IS DISTINCT FROM 'finding_service_delegated' OR a.body->'grant' IS DISTINCT FROM zasp_temporal78.grant_evidence(g) OR a.event_digest IS DISTINCT FROM digest(convert_to(a.body::text,'UTF8'),'sha256')
  THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding migration provenance changed';END IF;
  found_value:=true;
 END LOOP;
 RETURN found_value;
END $migrated$;

INSERT INTO zasp_temporal78.predecessor_functions SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'public.zasp_security_agent_schedule_triggers_v21(text,integer)'::regprocedure,
 'public.zasp_security_agent_schedule_triggers_v22(text,integer)'::regprocedure,
 'public.zasp_security_agent_schedule_triggers_v23(text,integer)'::regprocedure,
 'public.zasp_security_agent_schedule_triggers_v24(text,integer)'::regprocedure,
 'public.zasp_security_agent_schedule_triggers_v33(text,integer)'::regprocedure,
 'zasp_temporal75.retained_body(text,integer,text,text)'::regprocedure);
DO $copies$ DECLARE v integer;p record;d text;needle text;BEGIN
 FOREACH v IN ARRAY ARRAY[21,22,23,24,33] LOOP
  SELECT * INTO STRICT p FROM zasp_temporal78.predecessor_functions WHERE signature::regprocedure=('public.zasp_security_agent_schedule_triggers_v'||v||'(text,integer)')::regprocedure;
  IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION 'finding retained scheduler owner changed';END IF;
  d:=replace(p.definition,'FUNCTION public.zasp_security_agent_schedule_triggers_v'||v||'(','FUNCTION zasp_temporal78.retained'||v||'(');
  IF v=21 THEN
   needle:=$old$WHERE definition.activation IN('supervised','autonomous')$old$;
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding retained candidate predecessor changed';END IF;
   d:=replace(d,needle,$new$WHERE NOT definition.body?'trigger_rules' AND NOT zasp_temporal78.definition_migrated(definition.organization_id,definition.workspace_id,definition.environment_id,definition.definition_id) AND definition.activation IN('supervised','autonomous')$new$);
  ELSE
   needle:='zasp_security_agent_schedule_triggers_v'||CASE v WHEN 22 THEN 21 WHEN 23 THEN 22 WHEN 24 THEN 23 WHEN 33 THEN 24 END||'(';
   IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding retained chain predecessor changed';END IF;
   d:=replace(d,needle,'zasp_temporal78.retained'||CASE v WHEN 22 THEN 21 WHEN 23 THEN 22 WHEN 24 THEN 23 WHEN 33 THEN 24 END||'(');
  END IF;
  EXECUTE d;
 END LOOP;
 SELECT * INTO STRICT p FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal75.retained_body(text,integer,text,text)';
 IF p.owner_name<>'zasp_discovery_authority' THEN RAISE EXCEPTION 'finding retained body owner changed';END IF;
 d:=replace(p.definition,'FUNCTION zasp_temporal75.retained_body(','FUNCTION zasp_temporal78.retained_body(');
 needle:='public.zasp_security_agent_schedule_triggers_v33(';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding retained fallback predecessor changed';END IF;
 EXECUTE replace(d,needle,'zasp_temporal78.retained33(');
END $copies$;
CREATE FUNCTION zasp_temporal78.retained_schedule(worker_value text,limit_value integer,expected_checksum text,expected_fingerprint text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $retained$
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('zasp-schema-migrations',0));
 PERFORM zasp_temporal70.require_worker();
 IF NOT zasp_temporal78.current_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='finding retained catalog unavailable';END IF;
 RETURN zasp_temporal78.retained_body(worker_value,limit_value,expected_checksum,expected_fingerprint);
END $retained$;
