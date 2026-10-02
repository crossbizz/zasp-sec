-- Delivery is staged. P3 must exclude legacy selectors before granting a run
-- Temporal ownership. This release exposes no owner-change function.
SET LOCAL lock_timeout='3s';
CREATE SCHEMA zasp_temporal65 AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_temporal65 FROM PUBLIC;
CREATE TABLE zasp_temporal65.registration(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),checksum text NOT NULL,fingerprint text NOT NULL,predecessor text NOT NULL CHECK(predecessor IN('legacy60','ordered62')));
CREATE TABLE zasp_temporal65.commands(
 organization_id text NOT NULL CHECK(public.zasp_valid_product_id(organization_id)),
 workspace_id text NOT NULL CHECK(public.zasp_valid_product_id(workspace_id)),
 environment_id text NOT NULL CHECK(public.zasp_valid_product_id(environment_id)),
 run_id text NOT NULL CHECK(public.zasp_valid_product_id(run_id)),
 event_id text NOT NULL CHECK(public.zasp_valid_product_id(event_id)),
 kind text NOT NULL CHECK(kind IN('start','approval','cancel')),
 decision_id text CHECK(decision_id IS NULL OR public.zasp_valid_product_id(decision_id)),
 definition_version bigint NOT NULL CHECK(definition_version BETWEEN 1 AND 1000000),
 input_digest text NOT NULL CHECK(input_digest~'^[a-f0-9]{64}$'),
 execution_owner text NOT NULL DEFAULT 'legacy' CHECK(execution_owner IN('legacy','temporal')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,last_attempt_at timestamptz,
 PRIMARY KEY(organization_id,workspace_id,environment_id,event_id),
 CHECK((kind='start')=(decision_id IS NULL)),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id)
);
CREATE UNIQUE INDEX one_start ON zasp_temporal65.commands(organization_id,workspace_id,environment_id,run_id) WHERE kind='start';
CREATE INDEX pending_commands ON zasp_temporal65.commands((COALESCE(last_attempt_at,created_at)),created_at,organization_id,workspace_id,environment_id,event_id) WHERE accepted_at IS NULL AND execution_owner='temporal';
ALTER TABLE zasp_temporal65.registration OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal65.commands OWNER TO zasp_discovery_authority;
ALTER TABLE zasp_temporal65.registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal65.registration FORCE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal65.commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE zasp_temporal65.commands FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON zasp_temporal65.registration USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
CREATE POLICY authority ON zasp_temporal65.commands USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');

CREATE FUNCTION zasp_temporal65.capture() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $capture$
DECLARE rr public.zasp_security_agent_runs%ROWTYPE; audit_row public.zasp_security_agent_audit%ROWTYPE;trigger_row public.zasp_security_agent_trigger_receipts%ROWTYPE;k text;existing zasp_temporal65.commands%ROWTYPE;
BEGIN
 IF NEW.operation NOT IN('runSecurityAgent','decideSecurityAgentApproval','cancelSecurityAgentRun') THEN RETURN NEW;END IF;
 IF NOT zasp_temporal65.ready('-- outbox65 checksum','-- outbox65 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='outbox admission unavailable';END IF;
 -- The persisted audit supplies run identity. Request bodies are not routing authority.
 SELECT * INTO STRICT audit_row FROM public.zasp_security_agent_audit WHERE (organization_id,workspace_id,environment_id,audit_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.audit_id);
 IF audit_row.actor_id IS DISTINCT FROM NEW.principal_id THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox tenant decision rejected';END IF;
 SELECT * INTO STRICT rr FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,audit_row.run_id);
 k:=CASE NEW.operation WHEN 'runSecurityAgent' THEN 'start' WHEN 'decideSecurityAgentApproval' THEN 'approval' ELSE 'cancel' END;
 IF NEW.intent_digest IS DISTINCT FROM digest(convert_to(NEW.intent::text,'UTF8'),'sha256') THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='outbox intent conflict';END IF;
 -- Retained legacy runs may predate trigger receipts. A decision references
 -- its own validated intent; it must not manufacture an admission command.
 trigger_row.trigger_digest:=NEW.intent_digest;
 IF k='approval' AND NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_approvals a WHERE (a.organization_id,a.workspace_id,a.environment_id,a.run_id,a.approval_id,a.approver_id)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,audit_row.approval_id,NEW.principal_id) AND a.state IN('approved','rejected') AND a.decided_at IS NOT NULL AND a.fresh_auth_at IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox approval decision absent';END IF;
 IF k='start' THEN
  SELECT * INTO STRICT trigger_row FROM public.zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,run_id,definition_id,trigger_id)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,rr.definition_id,rr.trigger_id);
  SELECT * INTO existing FROM zasp_temporal65.commands WHERE (organization_id,workspace_id,environment_id,run_id,kind)=(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,'start');
  IF FOUND THEN
   IF (existing.definition_version,existing.input_digest) IS DISTINCT FROM (rr.definition_version,encode(trigger_row.trigger_digest,'hex')) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='outbox start input conflict';END IF;
   RETURN NEW;
  END IF;
 END IF;
 INSERT INTO zasp_temporal65.commands(organization_id,workspace_id,environment_id,run_id,event_id,kind,decision_id,definition_version,input_digest)
 VALUES(rr.organization_id,rr.workspace_id,rr.environment_id,rr.run_id,NEW.receipt_id,k,CASE WHEN k<>'start' THEN NEW.receipt_id END,rr.definition_version,encode(trigger_row.trigger_digest,'hex'));
 RETURN NEW;
END $capture$;
CREATE TRIGGER zasp_temporal65_capture AFTER INSERT ON public.zasp_security_agent_request_receipts FOR EACH ROW EXECUTE FUNCTION zasp_temporal65.capture();

CREATE FUNCTION zasp_temporal65.fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_temporal65'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,COALESCE(p.proacl::text,''),replace(replace(pg_get_functiondef(p.oid),'-- outbox65 checksum','<checksum>'),'-- outbox65 fingerprint','<fingerprint>')) FROM pg_proc p WHERE p.pronamespace='zasp_temporal65'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_temporal65'::regnamespace
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_temporal65'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_temporal65'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t WHERE t.tgname='zasp_temporal65_capture' AND t.tgrelid='public.zasp_security_agent_request_receipts'::regclass
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION zasp_temporal65.ready(c text,f text) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
DECLARE p text;
BEGIN
 IF c IS DISTINCT FROM '-- outbox65 checksum' OR f IS DISTINCT FROM '-- outbox65 fingerprint' OR (SELECT count(*) FROM zasp_temporal65.registration)<>1 OR zasp_temporal65.fingerprint() IS DISTINCT FROM f THEN RETURN false;END IF;
 SELECT predecessor INTO p FROM zasp_temporal65.registration WHERE checksum=c AND fingerprint=f;
 IF p='legacy60' THEN
  RETURN to_regnamespace('zasp_ordered_public62') IS NULL AND public.zasp_discovery_schedule_replay_readiness('-- release60 checksum','-- release60 fingerprint');
 ELSIF p='ordered62' THEN
  IF to_regnamespace('zasp_ordered_public62') IS NULL THEN RETURN false;END IF;
  RETURN zasp_ordered_public62.ready('-- public62 checksum','-- public62 fingerprint');
 END IF;
 RETURN false;
END
$ready$;
CREATE FUNCTION zasp_temporal65.pending() RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $pending$
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_temporal65.ready('-- outbox65 checksum','-- outbox65 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox relay unavailable';END IF;
 RETURN (SELECT COALESCE(jsonb_agg(jsonb_build_object('ref',jsonb_build_object('organization_id',c.organization_id,'workspace_id',c.workspace_id,'environment_id',c.environment_id,'run_id',c.run_id),'event_id',c.event_id,'kind',c.kind,'decision_id',COALESCE(c.decision_id,''),'definition_version',c.definition_version,'input_digest',c.input_digest,'execution_owner',c.execution_owner) ORDER BY COALESCE(c.last_attempt_at,c.created_at),c.created_at,c.organization_id,c.workspace_id,c.environment_id,c.event_id),'[]'::jsonb)
 FROM (SELECT x.* FROM zasp_temporal65.commands x WHERE x.accepted_at IS NULL AND x.execution_owner='temporal' AND (x.kind='start' OR EXISTS(SELECT 1 FROM zasp_temporal65.commands s WHERE (s.organization_id,s.workspace_id,s.environment_id,s.run_id,s.kind)=(x.organization_id,x.workspace_id,x.environment_id,x.run_id,'start') AND s.accepted_at IS NOT NULL)) ORDER BY COALESCE(x.last_attempt_at,x.created_at),x.created_at,x.organization_id,x.workspace_id,x.environment_id,x.event_id LIMIT 100) c);
END $pending$;
-- A durable polling turn, not a workflow lease or retry scheduler. Record it
-- before delivery so even a deadline-expired RPC cannot pin the queue prefix.
CREATE FUNCTION zasp_temporal65.attempt(o text,w text,e text,r text,event text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $attempt$
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_temporal65.ready('-- outbox65 checksum','-- outbox65 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox relay unavailable';END IF;
 UPDATE zasp_temporal65.commands SET last_attempt_at=clock_timestamp() WHERE (organization_id,workspace_id,environment_id,run_id,event_id,execution_owner)=(o,w,e,r,event,'temporal') AND accepted_at IS NULL;
 RETURN to_jsonb(FOUND);
END $attempt$;
CREATE FUNCTION zasp_temporal65.ack(o text,w text,e text,r text,event text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ack$
BEGIN
 IF NOT public.zasp_security_agent_principal_ready('zasp_security_agent_worker') OR NOT zasp_temporal65.ready('-- outbox65 checksum','-- outbox65 fingerprint') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='outbox relay unavailable';END IF;
 UPDATE zasp_temporal65.commands SET accepted_at=COALESCE(accepted_at,clock_timestamp()) WHERE (organization_id,workspace_id,environment_id,run_id,event_id,execution_owner)=(o,w,e,r,event,'temporal');
 RETURN to_jsonb(FOUND);
END $ack$;
DO $ownership$ DECLARE p record;BEGIN
 FOR p IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace='zasp_temporal65'::regnamespace LOOP
 EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p.signature);
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p.signature);
 END LOOP;
END $ownership$;
REVOKE ALL ON ALL TABLES IN SCHEMA zasp_temporal65 FROM PUBLIC;
GRANT USAGE ON SCHEMA zasp_temporal65 TO zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal65.ready(text,text) TO zasp_security_agent_api,zasp_security_agent_worker;
GRANT EXECUTE ON FUNCTION zasp_temporal65.pending(),zasp_temporal65.attempt(text,text,text,text,text),zasp_temporal65.ack(text,text,text,text,text) TO zasp_security_agent_worker;
