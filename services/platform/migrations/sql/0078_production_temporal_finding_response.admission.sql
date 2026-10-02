CREATE TABLE zasp_temporal78.run_owners(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,definition_id text NOT NULL,definition_version bigint NOT NULL,
 source_kind text NOT NULL CHECK(source_kind IN('automatic77','human78')),trigger_id text NOT NULL,trigger_version bigint NOT NULL,
 input_digest text NOT NULL CHECK(input_digest~'^[a-f0-9]{64}$'),snapshot jsonb NOT NULL,snapshot_digest bytea NOT NULL CHECK(snapshot_digest=digest(convert_to(snapshot::text,'UTF8'),'sha256')),
 action_key text NOT NULL CHECK(action_key='update_finding_response'),step_id text NOT NULL,workflow_id text NOT NULL UNIQUE,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE zasp_temporal78.commands(
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,run_id text NOT NULL,revision bigint NOT NULL CHECK(revision=1),kind text NOT NULL CHECK(kind='start'),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES zasp_temporal78.run_owners);
DO $tables$ DECLARE n text;BEGIN
 FOREACH n IN ARRAY ARRAY['run_owners','commands'] LOOP
  EXECUTE format('ALTER TABLE zasp_temporal78.%I OWNER TO zasp_discovery_authority',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE zasp_temporal78.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority ON zasp_temporal78.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',n);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON zasp_temporal78.%I FOR EACH STATEMENT EXECUTE FUNCTION zasp_temporal67.immutable()',n);
 END LOOP;
END $tables$;
CREATE FUNCTION zasp_temporal78.is_owned(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $owned$
 SELECT EXISTS(SELECT 1 FROM zasp_temporal78.run_owners WHERE(organization_id,workspace_id,environment_id,run_id)=(o,w,e,r))
$owned$;
CREATE FUNCTION zasp_temporal78.authorize(o text,w text,e text,d text,v bigint) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $authorize$
DECLARE row_value public.zasp_security_agent_definitions%ROWTYPE;h public.zasp_security_agent_definition_versions%ROWTYPE;g zasp_temporal78.service_grants%ROWTYPE;proof public.zasp_security_agent_audit%ROWTYPE;
BEGIN
 IF NOT zasp_temporal78.current_ready() OR NOT zasp_temporal68.principal_ready('zasp_temporal_executor') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding service authority unavailable';END IF;
 SELECT * INTO row_value FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 IF row_value.body->'allowed_actions' IS DISTINCT FROM '["update_finding_response"]'::jsonb THEN RETURN zasp_temporal74.authorize(o,w,e,d,v);END IF;
 SELECT * INTO h FROM public.zasp_security_agent_definition_versions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) FOR SHARE;
 SELECT * INTO g FROM zasp_temporal78.service_grants WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v) FOR SHARE;
 IF NOT zasp_temporal78.capable(row_value.body) OR row_value.activation NOT IN('supervised','autonomous') OR row_value.body->>'autonomy' IS DISTINCT FROM row_value.activation OR row_value.body->'enabled' IS DISTINCT FROM 'true'::jsonb OR NOT COALESCE(row_value.body->'environment_ids'?e,false)
 OR g.definition_id IS NULL OR h.definition IS DISTINCT FROM row_value.body OR h.activation IS DISTINCT FROM row_value.activation OR h.definition_digest IS DISTINCT FROM digest(convert_to(row_value.body::text,'UTF8'),'sha256') OR g.definition_digest IS DISTINCT FROM h.definition_digest
 OR g.principal_id IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_definition_service',d)
 OR EXISTS(SELECT 1 FROM zasp_temporal78.grant_revocations WHERE(organization_id,workspace_id,environment_id,definition_id,definition_version)=(o,w,e,d,v)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding service grant unavailable';END IF;
 SELECT * INTO proof FROM public.zasp_security_agent_audit WHERE(organization_id,workspace_id,environment_id,audit_id)=(o,w,e,g.audit_id) FOR SHARE;
 IF proof.actor_id IS DISTINCT FROM g.grantor_id OR proof.event_kind IS DISTINCT FROM 'finding_service_delegated' OR proof.body->'grant' IS DISTINCT FROM zasp_temporal78.grant_evidence(g) OR proof.event_digest IS DISTINCT FROM digest(convert_to(proof.body::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding delegation proof unavailable';END IF;
 PERFORM zasp_temporal78.manager(o,w,e,g.grantor_id);
 PERFORM public.zasp_production_security_agent_existing_tests_controls_guard(o,w,e,g.action_key);
 RETURN jsonb_build_object('principal_id',g.principal_id,'definition_id',d,'definition_version',v,'action_key',g.action_key);
END $authorize$;

CREATE FUNCTION zasp_temporal78.admit_body(o text,w text,e text,d text,v bigint,k text,t text,tv bigint,r text,actor_value text,audit_value text,correlation_value text,automatic_value boolean) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE def public.zasp_security_agent_definitions%ROWTYPE;src public.zasp_risk_findings%ROWTYPE;occ zasp_temporal77.occurrences%ROWTYPE;rr public.zasp_security_agent_runs%ROWTYPE;g jsonb;trigger_digest bytea;step_value text;
BEGIN
 SELECT * INTO def FROM public.zasp_security_agent_definitions WHERE(organization_id,workspace_id,environment_id,definition_id,version)=(o,w,e,d,v) AND deleted_at IS NULL FOR SHARE;
 IF def.body->'allowed_actions' IS DISTINCT FROM '["update_finding_response"]'::jsonb THEN RETURN zasp_temporal75.admit_body(o,w,e,d,v,k,t,tv,r,actor_value,audit_value,correlation_value,automatic_value);END IF;
 g:=zasp_temporal78.authorize(o,w,e,d,v);
 IF automatic_value IS DISTINCT FROM true OR k<>'finding' OR actor_value IS DISTINCT FROM g->>'principal_id' OR r IS DISTINCT FROM public.zasp_discovery_canonical_id(o,w,e,'security_agent_run',concat_ws(chr(31),d,v,k,t,tv)) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='finding admission identity rejected';END IF;
 SELECT * INTO src FROM public.zasp_risk_findings WHERE(organization_id,workspace_id,environment_id,id,version,status)=(o,w,e,t,tv,'open') AND rule=def.body->>'trigger_source' FOR SHARE;
 SELECT a.* INTO occ FROM zasp_temporal77.occurrences a JOIN zasp_temporal77.source_events s USING(organization_id,workspace_id,environment_id,event_id)
 WHERE(a.organization_id,a.workspace_id,a.environment_id,a.definition_id,a.definition_version,a.run_id,a.disposition,s.source_kind,s.source_id,s.source_version)=(o,w,e,d,v,r,'admitted',k,t,tv);
 IF src.id IS NULL OR occ.run_id IS NULL OR occ.definition_digest IS DISTINCT FROM digest(convert_to(def.body::text,'UTF8'),'sha256') OR occ.snapshot_digest IS DISTINCT FROM digest(convert_to(occ.snapshot::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='finding admission evidence changed';END IF;
 trigger_digest:=digest(convert_to(jsonb_build_object('kind','finding','id',t,'version',tv)::text,'UTF8'),'sha256');
 step_value:=public.zasp_discovery_canonical_id(o,w,e,'security_agent_step',r||chr(31)||'0');
 INSERT INTO zasp_temporal78.run_owners VALUES(o,w,e,r,d,v,'automatic77',t,tv,encode(trigger_digest,'hex'),occ.snapshot,occ.snapshot_digest,'update_finding_response',step_value,'security-agent-finding/v1/'||o||'/'||w||'/'||e||'/'||r,clock_timestamp());
 INSERT INTO public.zasp_security_agent_trigger_receipts(organization_id,workspace_id,environment_id,definition_id,trigger_id,trigger_kind,trigger_version,trigger_digest,run_id) VALUES(o,w,e,d,t,k,tv,trigger_digest,r);
 --73's unchanged row guard owns cross-family definition capacity.
 INSERT INTO public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state) VALUES(o,w,e,r,d,v,t,actor_value,'queued') RETURNING * INTO rr;
 INSERT INTO zasp_temporal78.commands VALUES(o,w,e,r,1,'start');
 INSERT INTO zasp_temporal78.start_deliveries(organization_id,workspace_id,environment_id,run_id) VALUES(o,w,e,r);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,run_id,actor_id,event_kind,event_digest,body)
 VALUES(o,w,e,audit_value,correlation_value,r,actor_value,'run_queued',trigger_digest,jsonb_build_object('run_id',r,'definition_id',d,'definition_version',v,'trigger_kind',k,'trigger_id',t,'trigger_version',tv,'automatic',true,'action','update_finding_response'));
 PERFORM zasp_temporal78.authorize(o,w,e,d,v);
 UPDATE public.zasp_security_agent_execution_state SET used_at=COALESCE(used_at,clock_timestamp()) WHERE singleton;
 RETURN jsonb_build_object('id',r,'agent_id',d,'state',rr.state,'evidence_ids',jsonb_build_array(t),'definition_version',v,'version',rr.version,'created',true,'replayed',false);
END $admit$;

INSERT INTO zasp_temporal78.predecessor_functions
 SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc WHERE oid IN(
 'zasp_temporal77.admit_occurrence(jsonb)'::regprocedure,'zasp_temporal77.desired(jsonb)'::regprocedure,'zasp_temporal77.references(text,integer)'::regprocedure,
 'zasp_temporal74.visible(text,text,text,text)'::regprocedure,'zasp_temporal76.executor74_fingerprint()'::regprocedure,'zasp_temporal76.fingerprint()'::regprocedure,
 'zasp_temporal75.desired(jsonb)'::regprocedure,'zasp_temporal75.references(text,integer)'::regprocedure);
DO $source$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal77.admit_occurrence(jsonb)';
 IF (length(d)-length(replace(d,'zasp_temporal74.authorize(','')))/length('zasp_temporal74.authorize(')<>2 OR (length(d)-length(replace(d,'zasp_temporal75.admit_body(','')))/length('zasp_temporal75.admit_body(')<>1 THEN RAISE EXCEPTION 'finding source authority predecessor changed';END IF;
 d:=replace(d,'FUNCTION zasp_temporal77.admit_occurrence(','FUNCTION zasp_temporal78.admit_occurrence(');
 d:=replace(d,'zasp_temporal74.authorize(','zasp_temporal78.authorize(');
 EXECUTE replace(d,'zasp_temporal75.admit_body(','zasp_temporal78.admit_body(');
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal75.desired(jsonb)';
 d:=replace(d,'FUNCTION zasp_temporal75.desired(','FUNCTION zasp_temporal78.desired_base(');
 needle:=$old$d.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)$old$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding desired predecessor changed';END IF;
 EXECUTE replace(d,needle,'('||needle||' OR zasp_temporal78.capable(d.body))');
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal77.desired(jsonb)';
 d:=replace(d,'FUNCTION zasp_temporal77.desired(','FUNCTION zasp_temporal78.desired(');
 EXECUTE replace(d,'zasp_temporal75.desired(q)','zasp_temporal78.desired_base(q)');
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature::regprocedure='zasp_temporal75.references(text,integer)'::regprocedure;
 d:=replace(d,'FUNCTION zasp_temporal75."references"(','FUNCTION zasp_temporal78."references"(');
 needle:=$old$d.body->'allowed_actions' IN('["run_test"]'::jsonb,'["rerun_test"]'::jsonb)$old$;
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'finding references predecessor changed';END IF;
 EXECUTE replace(d,needle,'('||needle||$new$ OR d.body->'allowed_actions'='["update_finding_response"]'::jsonb OR EXISTS(SELECT 1 FROM zasp_temporal78.service_grants f WHERE(f.organization_id,f.workspace_id,f.environment_id,f.definition_id)=(d.organization_id,d.workspace_id,d.environment_id,d.definition_id)))$new$);
END $source$;
CREATE OR REPLACE FUNCTION zasp_temporal77.admit_occurrence(q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
 SELECT zasp_temporal78.admit_occurrence(q)
$admit$;
CREATE OR REPLACE FUNCTION zasp_temporal77.desired(q jsonb) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $desired$
 SELECT zasp_temporal78.desired(q)
$desired$;
CREATE OR REPLACE FUNCTION zasp_temporal77.references(after_value text,limit_value integer) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $references$
 SELECT zasp_temporal78.references(after_value,limit_value)
$references$;
CREATE OR REPLACE FUNCTION zasp_temporal74.visible(o text,w text,e text,r text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $visible$
 SELECT (NOT zasp_temporal74.is_owned(o,w,e,r) AND NOT zasp_temporal78.is_owned(o,w,e,r)) OR public.zasp_security_agent_principal_ready('zasp_security_agent_api') OR zasp_temporal68.principal_ready('zasp_temporal_executor') OR zasp_temporal68.principal_ready('zasp_temporal_compensation')
$visible$;
DO $project76$ DECLARE d text;needle text;BEGIN
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal76.executor74_fingerprint()';
 needle:='ELSE pg_get_functiondef(p.oid) END';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>4 THEN RAISE EXCEPTION 'finding effective74 projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$projection$WHEN p.oid='zasp_temporal74.visible(text,text,text,text)'::regprocedure THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
 SELECT definition INTO STRICT d FROM zasp_temporal78.predecessor_functions WHERE signature='zasp_temporal76.fingerprint()';
 d:=replace(d,'FUNCTION zasp_temporal76.fingerprint()','FUNCTION zasp_temporal78.predecessor76_fingerprint()');
 needle:='pg_get_functiondef(p.oid)';
 IF (length(d)-length(replace(d,needle,'')))/length(needle)<>2 THEN RAISE EXCEPTION 'finding76 projection predecessor changed';END IF;
 EXECUTE replace(d,needle,$projection$CASE WHEN p.oid IN('zasp_temporal76.executor74_fingerprint()'::regprocedure,'zasp_temporal76.fingerprint()'::regprocedure) THEN (SELECT definition FROM zasp_temporal78.predecessor_functions WHERE signature=p.oid::regprocedure::text) ELSE pg_get_functiondef(p.oid) END$projection$);
END $project76$;
CREATE OR REPLACE FUNCTION zasp_temporal76.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 SELECT CASE WHEN zasp_temporal78.catalog_ready() THEN zasp_temporal78.predecessor76_fingerprint() ELSE NULL END
$fingerprint$;
