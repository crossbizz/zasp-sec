-- The capability has no login or steady-state memberships. Caller identity is
-- always session_user; guards run as invokers so a migration login cannot DML.
CREATE ROLE zasp_security_agent_global_operator NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT zasp_security_agent_global_operator TO CURRENT_USER;
GRANT USAGE,CREATE ON SCHEMA public TO zasp_security_agent_global_operator;

CREATE TABLE zasp_existing_tests_predecessor.global_control_triggers (
 relation_name text PRIMARY KEY, trigger_name text NOT NULL, definition text NOT NULL, enabled "char" NOT NULL
);
ALTER TABLE zasp_existing_tests_predecessor.global_control_triggers OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_existing_tests_predecessor.global_control_triggers FROM PUBLIC;
INSERT INTO zasp_existing_tests_predecessor.global_control_triggers
 SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid,true),t.tgenabled
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
 WHERE t.tgrelid IN('public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass)
 AND t.tgname=c.relname||'_recovery_hold' AND NOT t.tgisinternal;
DO $saved$
BEGIN
 IF (SELECT count(*) FROM zasp_existing_tests_predecessor.global_control_triggers)<>2 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global predecessor triggers unavailable';
 END IF;
END
$saved$;

CREATE TABLE public.zasp_security_agent_global_control_receipts (
 request_id text PRIMARY KEY CHECK(public.zasp_valid_product_id(request_id)),
 caller_session text NOT NULL CHECK(length(caller_session) BETWEEN 1 AND 63),
 enabled boolean NOT NULL,
 expected_version bigint NOT NULL CHECK(expected_version>0 AND expected_version<9223372036854775807),
 correlation_id text NOT NULL CHECK(octet_length(correlation_id) BETWEEN 1 AND 128 AND correlation_id COLLATE "C" ~ '^[!-~]+$'),
 resulting_version bigint NOT NULL CHECK(resulting_version=expected_version+1),
 result jsonb NOT NULL CHECK(result=jsonb_build_object('enabled',enabled,'version',resulting_version,'replayed',false)),
 transaction_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
ALTER TABLE public.zasp_security_agent_global_control_receipts OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_security_agent_global_control_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_security_agent_global_control_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON public.zasp_security_agent_global_control_receipts FROM PUBLIC;
CREATE POLICY global_receipt_authority ON public.zasp_security_agent_global_control_receipts TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY global_receipt_operator ON public.zasp_security_agent_global_control_receipts TO zasp_security_agent_global_operator USING(true) WITH CHECK(caller_session=session_user);
GRANT SELECT,INSERT ON public.zasp_security_agent_global_control_receipts TO zasp_security_agent_global_operator;
GRANT SELECT ON public.zasp_security_agent_kill_switches,public.zasp_security_agent_audit TO zasp_security_agent_global_operator;
GRANT UPDATE(execution_enabled,version,updated_by,updated_at) ON public.zasp_security_agent_kill_switches TO zasp_security_agent_global_operator;
GRANT INSERT ON public.zasp_security_agent_audit TO zasp_security_agent_global_operator;
GRANT SELECT(principal_name,authority_role) ON public.zasp_discovery_principal_bindings TO zasp_security_agent_global_operator;
CREATE POLICY global_operator_binding ON public.zasp_discovery_principal_bindings FOR SELECT TO zasp_security_agent_global_operator USING(principal_name=session_user AND authority_role='zasp_discovery_authority');
CREATE POLICY global_operator_control_read ON public.zasp_security_agent_kill_switches FOR SELECT TO zasp_security_agent_global_operator USING((organization_id,workspace_id,environment_id,action_key)=('*','*','*','*'));
CREATE POLICY global_operator_control_write ON public.zasp_security_agent_kill_switches FOR UPDATE TO zasp_security_agent_global_operator USING((organization_id,workspace_id,environment_id,action_key)=('*','*','*','*')) WITH CHECK((organization_id,workspace_id,environment_id,action_key)=('*','*','*','*'));
CREATE POLICY global_operator_audit_read ON public.zasp_security_agent_audit FOR SELECT TO zasp_security_agent_global_operator USING((organization_id,workspace_id,environment_id,event_kind)=('*','*','*','kill_switch_changed'));
CREATE POLICY global_operator_audit_write ON public.zasp_security_agent_audit FOR INSERT TO zasp_security_agent_global_operator WITH CHECK((organization_id,workspace_id,environment_id,event_kind)=('*','*','*','kill_switch_changed'));
GRANT EXECUTE ON FUNCTION public.zasp_production_security_agent_existing_tests_readiness(text,text) TO zasp_security_agent_global_operator;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_principal_ready()
RETURNS boolean LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path TO pg_catalog,public AS $principal$
 SELECT current_user='zasp_security_agent_global_operator'
 AND pg_has_role(session_user,'zasp_discovery_authority','MEMBER')
 AND EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority')
$principal$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_intent(r public.zasp_security_agent_global_control_receipts)
RETURNS jsonb LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path TO pg_catalog,public AS $intent$
 SELECT jsonb_build_object('request_id',r.request_id,'actor',r.caller_session,'enabled',r.enabled,'expected_version',r.expected_version,'correlation_id',r.correlation_id,'version',r.resulting_version,'action_key','*')
$intent$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_receipt_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO pg_catalog,public AS $guard$
BEGIN
 IF TG_OP<>'INSERT' OR NOT public.zasp_production_security_agent_existing_tests_global_principal_ready()
  OR NEW.caller_session IS DISTINCT FROM session_user OR NEW.transaction_id IS DISTINCT FROM pg_current_xact_id()
  OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
  OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') AND version=NEW.expected_version) THEN
  RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global receipt authority rejected';
 END IF;
 RETURN NEW;
END
$guard$;

-- Deferred association closes the receipt/control/audit cycle. It does not
-- authorize writes and must work after the entrypoint has restored current_user.
CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_receipt_complete()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO pg_catalog,public AS $complete$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_audit a
  WHERE (a.organization_id,a.workspace_id,a.environment_id,a.audit_id)=('*','*','*',NEW.request_id)
  AND a.actor_id=NEW.caller_session AND a.correlation_id=NEW.correlation_id AND a.event_kind='kill_switch_changed'
  AND a.run_id IS NULL AND a.step_id IS NULL AND a.approval_id IS NULL
  AND a.body=public.zasp_production_security_agent_existing_tests_global_intent(NEW)
  AND a.event_digest=digest(convert_to(a.body::text,'UTF8'),'sha256') AND a.created_at=NEW.created_at)
 OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') AND version>=NEW.resulting_version) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global receipt association missing';
 END IF;
 RETURN NEW;
END
$complete$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_control_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO pg_catalog,public AS $guard$
BEGIN
 IF (TG_OP IN('UPDATE','DELETE') AND '*' IN(OLD.organization_id,OLD.workspace_id,OLD.environment_id))
  OR (TG_OP IN('INSERT','UPDATE') AND '*' IN(NEW.organization_id,NEW.workspace_id,NEW.environment_id)) THEN
  IF TG_OP<>'UPDATE' OR NOT public.zasp_production_security_agent_existing_tests_global_principal_ready()
   OR (OLD.organization_id,OLD.workspace_id,OLD.environment_id,OLD.action_key) IS DISTINCT FROM ('*','*','*','*')
   OR (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.action_key) IS DISTINCT FROM ('*','*','*','*')
   OR NEW.version<>OLD.version+1 OR NEW.updated_by IS DISTINCT FROM session_user OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_global_control_receipts r
    WHERE r.transaction_id=pg_current_xact_id() AND r.caller_session=session_user AND r.enabled=NEW.execution_enabled
    AND r.expected_version=OLD.version AND r.resulting_version=NEW.version) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global control authority rejected';
  END IF;
 ELSE
  IF TG_OP IN('UPDATE','DELETE') AND NOT public.zasp_recovery_scope_mutable(OLD.organization_id,OLD.workspace_id,OLD.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
  IF TG_OP IN('INSERT','UPDATE') AND NOT public.zasp_recovery_scope_mutable(NEW.organization_id,NEW.workspace_id,NEW.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END
$guard$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_audit_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path TO pg_catalog,public AS $guard$
BEGIN
 IF (TG_OP IN('UPDATE','DELETE') AND '*' IN(OLD.organization_id,OLD.workspace_id,OLD.environment_id))
  OR (TG_OP IN('INSERT','UPDATE') AND '*' IN(NEW.organization_id,NEW.workspace_id,NEW.environment_id)) THEN
  IF TG_OP<>'INSERT' OR NOT public.zasp_production_security_agent_existing_tests_global_principal_ready()
   OR (NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.event_kind) IS DISTINCT FROM ('*','*','*','kill_switch_changed')
   OR NEW.actor_id IS DISTINCT FROM session_user OR NEW.run_id IS NOT NULL OR NEW.step_id IS NOT NULL OR NEW.approval_id IS NOT NULL
   OR NOT EXISTS(SELECT 1 FROM public.zasp_security_agent_global_control_receipts r
    JOIN public.zasp_security_agent_kill_switches c ON (c.organization_id,c.workspace_id,c.environment_id,c.action_key)=('*','*','*','*')
    WHERE r.request_id=NEW.audit_id AND r.transaction_id=pg_current_xact_id() AND r.caller_session=session_user
    AND c.version=r.resulting_version AND c.execution_enabled=r.enabled AND c.updated_by=r.caller_session AND c.updated_at=r.created_at
    AND NEW.correlation_id=r.correlation_id AND NEW.created_at=r.created_at
    AND NEW.body=public.zasp_production_security_agent_existing_tests_global_intent(r)
    AND NEW.event_digest=digest(convert_to(NEW.body::text,'UTF8'),'sha256')) THEN
   RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global audit authority rejected';
  END IF;
 ELSE
  IF TG_OP IN('UPDATE','DELETE') AND NOT public.zasp_recovery_scope_mutable(OLD.organization_id,OLD.workspace_id,OLD.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
  IF TG_OP IN('INSERT','UPDATE') AND NOT public.zasp_recovery_scope_mutable(NEW.organization_id,NEW.workspace_id,NEW.environment_id) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='tenant recovery hold active';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END
$guard$;

CREATE TRIGGER global_receipt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_global_control_receipts FOR EACH ROW EXECUTE FUNCTION public.zasp_production_security_agent_existing_tests_global_receipt_guard();
CREATE CONSTRAINT TRIGGER global_receipt_complete AFTER INSERT ON public.zasp_security_agent_global_control_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.zasp_production_security_agent_existing_tests_global_receipt_complete();
DROP TRIGGER zasp_security_agent_kill_switches_recovery_hold ON public.zasp_security_agent_kill_switches;
CREATE TRIGGER zasp_security_agent_kill_switches_recovery_hold BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_kill_switches FOR EACH ROW EXECUTE FUNCTION public.zasp_production_security_agent_existing_tests_global_control_guard();
DROP TRIGGER zasp_security_agent_audit_recovery_hold ON public.zasp_security_agent_audit;
CREATE TRIGGER zasp_security_agent_audit_recovery_hold BEFORE INSERT OR UPDATE OR DELETE ON public.zasp_security_agent_audit FOR EACH ROW EXECUTE FUNCTION public.zasp_production_security_agent_existing_tests_global_audit_guard();

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_read(expected_checksum text,expected_fingerprint text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $read$
DECLARE result_value jsonb;
BEGIN
 LOCK TABLE public.zasp_security_agent_global_control_receipts,public.zasp_security_agent_kill_switches,public.zasp_security_agent_audit IN ACCESS SHARE MODE;
 IF NOT public.zasp_production_security_agent_existing_tests_global_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global operator authority unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator release unavailable';END IF;
 SELECT jsonb_build_object('enabled',execution_enabled,'version',version,'replayed',false) INTO result_value
 FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*');
 IF result_value IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global control missing';END IF;
 RETURN result_value;
END
$read$;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_set(expected_checksum text,expected_fingerprint text,enabled_value boolean,expected_version bigint,request_value text,correlation_value text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $set$
DECLARE control_row public.zasp_security_agent_kill_switches%ROWTYPE; receipt_row public.zasp_security_agent_global_control_receipts%ROWTYPE; result_value jsonb; body_value jsonb;
BEGIN
 LOCK TABLE public.zasp_security_agent_global_control_receipts IN ROW EXCLUSIVE MODE;
 LOCK TABLE public.zasp_security_agent_kill_switches IN ACCESS SHARE MODE;
 LOCK TABLE public.zasp_security_agent_audit IN ROW EXCLUSIVE MODE;
 IF NOT public.zasp_production_security_agent_existing_tests_global_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global operator authority unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator release unavailable';END IF;
 IF NOT COALESCE(enabled_value IS NOT NULL AND expected_version>0 AND expected_version<9223372036854775807
  AND public.zasp_valid_product_id(request_value) AND octet_length(correlation_value) BETWEEN 1 AND 128 AND correlation_value COLLATE "C" ~ '^[!-~]+$',false) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='global operator intent rejected';
 END IF;
 SELECT * INTO control_row FROM public.zasp_security_agent_kill_switches WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*') FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global control missing';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_global_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global operator authority unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator release unavailable';END IF;
 SELECT * INTO receipt_row FROM public.zasp_security_agent_global_control_receipts WHERE request_id=request_value;
 IF FOUND THEN
  IF (receipt_row.caller_session,receipt_row.enabled,receipt_row.expected_version,receipt_row.correlation_id) IS DISTINCT FROM (session_user::text,enabled_value,expected_version,correlation_value) THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='global operator replay intent conflict';END IF;
  RETURN receipt_row.result||jsonb_build_object('replayed',true);
 END IF;
 IF control_row.version<>expected_version THEN RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='global operator version conflict';END IF;
 result_value:=jsonb_build_object('enabled',enabled_value,'version',control_row.version+1,'replayed',false);
 INSERT INTO public.zasp_security_agent_global_control_receipts(request_id,caller_session,enabled,expected_version,correlation_id,resulting_version,result)
 VALUES(request_value,session_user,enabled_value,expected_version,correlation_value,control_row.version+1,result_value) RETURNING * INTO receipt_row;
 UPDATE public.zasp_security_agent_kill_switches SET execution_enabled=enabled_value,version=control_row.version+1,updated_by=session_user,updated_at=transaction_timestamp()
 WHERE (organization_id,workspace_id,environment_id,action_key)=('*','*','*','*');
 body_value:=public.zasp_production_security_agent_existing_tests_global_intent(receipt_row);
 INSERT INTO public.zasp_security_agent_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,actor_id,event_kind,event_digest,body)
 VALUES('*','*','*',request_value,correlation_value,session_user,'kill_switch_changed',digest(convert_to(body_value::text,'UTF8'),'sha256'),body_value);
 IF NOT public.zasp_production_security_agent_existing_tests_global_principal_ready() THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='global operator authority unavailable';END IF;
 IF NOT public.zasp_production_security_agent_existing_tests_readiness(expected_checksum,expected_fingerprint) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global operator release unavailable';END IF;
 RETURN result_value;
END
$set$;

DO $owners$
DECLARE item record;
BEGIN
 FOR item IN SELECT oid,proname,pg_get_function_identity_arguments(oid) args FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_production_security_agent_existing_tests_global_') LOOP
  EXECUTE format('ALTER FUNCTION public.%I(%s) OWNER TO %I',item.proname,item.args,CASE WHEN item.proname IN('zasp_production_security_agent_existing_tests_global_read','zasp_production_security_agent_existing_tests_global_set') THEN 'zasp_security_agent_global_operator' ELSE 'zasp_discovery_authority' END);
  EXECUTE format('REVOKE ALL ON FUNCTION public.%I(%s) FROM PUBLIC',item.proname,item.args);
  EXECUTE format('GRANT EXECUTE ON FUNCTION public.%I(%s) TO zasp_discovery_authority,zasp_security_agent_global_operator',item.proname,item.args);
 END LOOP;
END
$owners$;
REVOKE zasp_security_agent_global_operator FROM CURRENT_USER;
REVOKE CREATE ON SCHEMA public FROM zasp_security_agent_global_operator;

CREATE FUNCTION public.zasp_production_security_agent_existing_tests_global_fingerprint()
RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path TO pg_catalog,public AS $fingerprint$
 WITH relations AS (
  SELECT c.oid FROM pg_class c WHERE c.oid IN('public.zasp_security_agent_global_control_receipts'::regclass,'public.zasp_security_agent_kill_switches'::regclass,'public.zasp_security_agent_audit'::regclass,'public.zasp_discovery_principal_bindings'::regclass,'zasp_existing_tests_predecessor.global_control_triggers'::regclass)
 ), identities(value) AS (
 SELECT concat_ws('|','role',rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,COALESCE(rolvaliduntil::text,''),COALESCE(rolconfig::text,'')) FROM pg_roles WHERE rolname='zasp_security_agent_global_operator'
 UNION ALL SELECT concat_ws('|','membership',roleid::regrole::text,member::regrole::text,grantor::regrole::text,admin_option) FROM pg_auth_members WHERE roleid='zasp_security_agent_global_operator'::regrole OR member='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','owned-function',p.oid::regprocedure::text,p.prosecdef,COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.proowner='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','owned-relation',c.oid::regclass::text,c.relkind) FROM pg_class c WHERE c.relowner='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','owned-schema',nspname) FROM pg_namespace WHERE nspowner='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','owned-database',datname) FROM pg_database WHERE datdba='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','default-acl',defaclrole::regrole::text,defaclnamespace::regnamespace::text,defaclobjtype,defaclacl::text) FROM pg_default_acl WHERE defaclrole='zasp_security_agent_global_operator'::regrole OR EXISTS(SELECT 1 FROM aclexplode(defaclacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole)
 UNION ALL SELECT concat_ws('|','table',c.oid::regclass::text,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity,c.relowner::regrole::text,COALESCE(c.relacl::text,''),COALESCE(c.reloptions::text,'')) FROM pg_class c WHERE c.oid IN(SELECT oid FROM relations)
 UNION ALL SELECT concat_ws('|','column',a.attrelid::regclass::text,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN(SELECT oid FROM relations) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',conrelid::regclass::text,conname,convalidated,pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conrelid IN(SELECT oid FROM relations)
 UNION ALL SELECT concat_ws('|','index',indrelid::regclass::text,indexrelid::regclass::text,indisvalid,indisready,indislive,pg_get_indexdef(indexrelid)) FROM pg_index WHERE indrelid IN(SELECT oid FROM relations)
 UNION ALL SELECT concat_ws('|','policy',polrelid::regclass::text,polname,polpermissive,polcmd,(SELECT string_agg(r::regrole::text,',' ORDER BY r::regrole::text) FROM unnest(polroles) r),pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid IN(SELECT oid FROM relations)
 UNION ALL SELECT concat_ws('|','trigger',tgrelid::regclass::text,tgname,tgenabled,pg_get_triggerdef(oid,true),tgfoid::regprocedure::text) FROM pg_trigger WHERE tgrelid IN(SELECT oid FROM relations) AND NOT tgisinternal
 UNION ALL SELECT concat_ws('|','saved-trigger',relation_name,trigger_name,definition,enabled) FROM zasp_existing_tests_predecessor.global_control_triggers
 -- Capture every capability grant, including unexpected grants outside these tables.
 UNION ALL SELECT concat_ws('|','relation-grant',c.oid::regclass::text,a.privilege_type,a.is_grantable,a.grantor::regrole::text) FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','column-grant',c.attrelid::regclass::text,c.attname,a.privilege_type,a.is_grantable,a.grantor::regrole::text) FROM pg_attribute c CROSS JOIN LATERAL aclexplode(c.attacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','function-grant',p.oid::regprocedure::text,a.privilege_type,a.is_grantable,a.grantor::regrole::text) FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole
 UNION ALL SELECT concat_ws('|','schema-grant',n.nspname,a.privilege_type,a.is_grantable,a.grantor::regrole::text) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE a.grantee='zasp_security_agent_global_operator'::regrole
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_production_security_agent_existing_tests_global_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_security_agent_existing_tests_global_fingerprint() FROM PUBLIC;
DO $extend_fingerprint$
DECLARE source_value text; needle text:=') SELECT encode(digest(convert_to(string_agg(value';
BEGIN
 source_value:=pg_get_functiondef('public.zasp_production_security_agent_existing_tests_live_fingerprint()'::regprocedure);
 IF (length(source_value)-length(replace(source_value,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='global fingerprint predecessor unavailable';END IF;
 source_value:=replace(source_value,needle,'UNION ALL SELECT concat_ws(''|'',''global'',public.zasp_production_security_agent_existing_tests_global_fingerprint()) '||needle);
 EXECUTE source_value;
END
$extend_fingerprint$;
