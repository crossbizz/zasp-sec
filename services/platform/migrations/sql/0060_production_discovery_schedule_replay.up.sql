SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
LOCK TABLE public.zasp_discovery_schedules IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.zasp_discovery_schedule_runs IN ACCESS EXCLUSIVE MODE;
DO $guard$
BEGIN
 IF NOT public.zasp_sa_webhook_readiness('-- schedule replay predecessor checksum','-- schedule replay predecessor fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay predecessor unavailable';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_discovery_schedule_runs GROUP BY organization_id,workspace_id,environment_id,schedule_id,scheduled_for HAVING count(*)>1) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay duplicate historical occurrence';END IF;
 IF EXISTS(SELECT 1 FROM public.zasp_discovery_schedule_runs WHERE completed_at IS NULL) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay incomplete historical occurrence';END IF;
END $guard$;

CREATE SCHEMA zasp_schedule_replay_prior AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_schedule_replay_prior FROM PUBLIC;
CREATE TABLE zasp_schedule_replay_prior.functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl jsonb NOT NULL);
ALTER TABLE zasp_schedule_replay_prior.functions OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_schedule_replay_prior.functions FROM PUBLIC;
DO $snapshot$
DECLARE sig text;p pg_proc%ROWTYPE;
BEGIN
 FOREACH sig IN ARRAY ARRAY[
 'public.zasp_compliance_readiness(text,text)',
 'public.zasp_production_security_agent_existing_tests_readiness(text,text)',
 'public.zasp_sa_attack_lab_readiness(text,text)',
 'zasp_sa_attack_lab_prior.predecessor_ready(text,text)',
 'zasp_sa_export_prior.predecessor_ready(text,text)',
 'public.zasp_sa_export_readiness(text,text)',
 'public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)',
 'public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)',
 'public.zasp_production_security_agent_attack_path_security_ready()',
 'public.zasp_production_workflow_compatibility_security_ready()',
 'zasp_sa_attack_lab_prior.audit_fingerprint()',
 'public.zasp_execution_live_fingerprint()',
 'public.zasp_execution_readiness(text,text)',
 'public.zasp_execution_security_ready()',
 'public.zasp_execution_request_scheduled_sync(text,text,text,text,text,text,text,text,text,text,text,text,bytea,text,text)',
 'public.zasp_execution_complete_schedule(text,text,text,text,text,text,text,timestamp with time zone)',
 'public.zasp_sa_webhook_readiness(text,text)',
 'public.zasp_sa_webhook_guard()',
 'zasp_sa_webhook_prior.predecessor_ready(text,text)'] LOOP
  SELECT * INTO STRICT p FROM pg_proc WHERE oid=sig::regprocedure;
  INSERT INTO zasp_schedule_replay_prior.functions SELECT sig,pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE((SELECT jsonb_agg(jsonb_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'grantable',a.is_grantable) ORDER BY a.ordinality) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) WITH ORDINALITY a WHERE a.privilege_type='EXECUTE'),'[]');
 END LOOP;
END $snapshot$;

ALTER TABLE public.zasp_discovery_schedule_runs
 ADD COLUMN rebind_generation bigint NOT NULL DEFAULT 0 CHECK(rebind_generation>=0),
 ADD COLUMN completion_digest bytea CHECK(completion_digest IS NULL OR octet_length(completion_digest)=32),
 ADD COLUMN completion_result jsonb,
 ADD CONSTRAINT zasp_discovery_schedule_runs_completion_pair CHECK((completion_digest IS NULL)=(completion_result IS NULL)),
 ADD CONSTRAINT zasp_discovery_schedule_runs_occurrence_key UNIQUE(organization_id,workspace_id,environment_id,schedule_id,scheduled_for);

DO $ancestry$
DECLARE saved record;d text;needle text;n integer;
BEGIN
 PERFORM set_config('check_function_bodies','off',true);
 FOR saved IN SELECT * FROM zasp_schedule_replay_prior.functions ORDER BY signature LOOP
  d:=saved.definition;
  IF strpos(saved.signature,'readiness(')>0 OR strpos(saved.signature,'predecessor_ready(')>0 THEN
   IF saved.signature='public.zasp_execution_readiness(text,text)' THEN CONTINUE;END IF;
   IF strpos(d,'count(*)=59')=0 OR strpos(d,'version>59')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay predecessor shape rejected';END IF;
   d:=replace(replace(d,'count(*)=59','count(*)=60'),'version>59','version>60');
   IF saved.signature='public.zasp_sa_webhook_readiness(text,text)' THEN
    EXECUTE replace(replace(d,'FUNCTION public.zasp_sa_webhook_readiness(','FUNCTION zasp_schedule_replay_prior.predecessor_ready('),'public.zasp_sa_webhook_live_fingerprint()=expected_fingerprint','true');
    ALTER FUNCTION zasp_schedule_replay_prior.predecessor_ready(text,text) OWNER TO zasp_discovery_authority;
    REVOKE ALL ON FUNCTION zasp_schedule_replay_prior.predecessor_ready(text,text) FROM PUBLIC;
    d:=replace(d,'public.zasp_sa_webhook_live_fingerprint()=expected_fingerprint','public.zasp_discovery_schedule_replay_guard()');
   END IF;
   EXECUTE d;
  ELSIF saved.signature IN('public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()') THEN
   n:=0;
   FOREACH needle IN ARRAY ARRAY['later_release."version" > 59','later."version">59','later."version" > 59'] LOOP
    n:=n+(length(d)-length(replace(d,needle,'')))/length(needle);
    d:=replace(d,needle,replace(needle,'59','60'));
   END LOOP;
   IF n NOT IN(1,3) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay compatibility rejected';END IF;
   EXECUTE d;
  ELSIF saved.signature='zasp_sa_attack_lab_prior.audit_fingerprint()' THEN
   needle:='''production_security_agent_webhooks_checksum'',''production_security_agent_webhooks_fingerprint''';
   IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='schedule replay ancestry rejected';END IF;
   EXECUTE replace(d,needle,needle||',''production_discovery_schedule_replay_checksum'',''production_discovery_schedule_replay_fingerprint''');
  END IF;
 END LOOP;
 PERFORM set_config('check_function_bodies','off',true);
END $ancestry$;

CREATE OR REPLACE FUNCTION public.zasp_execution_request_scheduled_sync(organization_value text,workspace_value text,environment_value text,principal_value text,schedule_value text,worker_value text,lease_token_value text,integration_value text,sync_value text,job_value text,outbox_value text,idempotency_value text,request_digest_value bytea,parser_value text,tool_value text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $admit$
DECLARE schedule_row zasp_discovery_schedules%ROWTYPE;result jsonb;affected integer;
BEGIN
 IF NOT public.zasp_execution_principal_ready('zasp_discovery_scheduler') AND NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied';END IF;
 SELECT * INTO schedule_row FROM zasp_discovery_schedules WHERE (organization_id,workspace_id,environment_id,id,integration_id,state,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,schedule_value,integration_value,'enabled',worker_value,lease_token_value) FOR UPDATE;
 IF NOT FOUND OR schedule_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;
 result:=zasp_execution_request_sync(organization_value,workspace_value,environment_value,principal_value,integration_value,sync_value,job_value,outbox_value,idempotency_value,request_digest_value,'schedule',parser_value,tool_value);
 IF (result->>'sync_id',result->>'job_id',result->>'outbox_id') IS DISTINCT FROM (sync_value,job_value,outbox_value) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule run conflict';END IF;
 INSERT INTO zasp_discovery_schedule_runs(organization_id,workspace_id,environment_id,schedule_id,sync_id,job_id,lease_owner,lease_token,request_digest,scheduled_for)
 VALUES(organization_value,workspace_value,environment_value,schedule_value,sync_value,job_value,worker_value,lease_token_value,request_digest_value,schedule_row.next_run_at)
 ON CONFLICT ON CONSTRAINT zasp_discovery_schedule_runs_occurrence_key DO NOTHING;
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected=0 THEN
  IF NOT EXISTS(SELECT 1 FROM zasp_discovery_schedule_runs r WHERE (r.organization_id,r.workspace_id,r.environment_id,r.schedule_id,r.scheduled_for,r.sync_id,r.job_id,r.request_digest,r.lease_owner,r.lease_token)=(organization_value,workspace_value,environment_value,schedule_value,schedule_row.next_run_at,sync_value,job_value,request_digest_value,worker_value,lease_token_value) AND r.completed_at IS NULL AND r.completion_digest IS NULL) THEN
   UPDATE zasp_discovery_schedule_runs r SET lease_owner=worker_value,lease_token=lease_token_value,rebind_generation=r.rebind_generation+1
   WHERE (r.organization_id,r.workspace_id,r.environment_id,r.schedule_id,r.scheduled_for,r.sync_id,r.job_id,r.request_digest)=(organization_value,workspace_value,environment_value,schedule_value,schedule_row.next_run_at,sync_value,job_value,request_digest_value) AND r.completed_at IS NULL AND r.completion_digest IS NULL AND (r.lease_owner,r.lease_token) IS DISTINCT FROM (worker_value,lease_token_value);
   GET DIAGNOSTICS affected=ROW_COUNT;
   IF affected<>1 THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule run conflict';END IF;
  END IF;
 END IF;
 IF schedule_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;
 RETURN result;
END $admit$;

CREATE OR REPLACE FUNCTION public.zasp_execution_complete_schedule(organization_value text,workspace_value text,environment_value text,schedule_value text,worker_value text,lease_token_value text,outcome_value text,next_run_value timestamptz) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path TO pg_catalog,public AS $complete$
DECLARE result jsonb;run_row zasp_discovery_schedule_runs%ROWTYPE;schedule_row zasp_discovery_schedules%ROWTYPE;digest_value bytea;
BEGIN
 IF NOT public.zasp_execution_principal_ready('zasp_discovery_scheduler') AND NOT EXISTS(SELECT 1 FROM public.zasp_discovery_principal_bindings WHERE principal_name=session_user AND authority_role='zasp_discovery_authority') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='scheduler authority denied';END IF;
 digest_value:=digest(convert_to(jsonb_build_array(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value,outcome_value,floor(extract(epoch FROM next_run_value)*1000000)::bigint)::text,'UTF8'),'sha256');
 -- Lock order matches admission. A stored completion is checked before any
 -- live lease or current-time predicate, including after a later claim.
 SELECT * INTO schedule_row FROM zasp_discovery_schedules WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,schedule_value) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;
 -- Non-advanced completion has no admitted run receipt. Match the predecessor's
 -- exact stored digest, then delegate its original validation and saved reply.
 -- In particular this path cannot turn an advanced request into a lease bypass.
 IF outcome_value IN('released','disabled') AND schedule_row.completion_digest=digest(convert_to(concat_ws(chr(31),schedule_value,worker_value,lease_token_value,outcome_value,floor(extract(epoch FROM next_run_value)*1000000)::bigint::text),'UTF8'),'sha256') THEN
  RETURN zasp_discovery_complete_schedule(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value,outcome_value,next_run_value);
 END IF;
 SELECT * INTO run_row FROM zasp_discovery_schedule_runs WHERE (organization_id,workspace_id,environment_id,schedule_id,lease_owner,lease_token)=(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value) FOR UPDATE;
 IF FOUND AND run_row.completion_digest IS NOT NULL THEN
  IF run_row.completion_digest IS DISTINCT FROM digest_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='schedule completion conflict';END IF;
  RETURN run_row.completion_result;
 END IF;
 IF (schedule_row.state,schedule_row.lease_owner,schedule_row.lease_token) IS DISTINCT FROM ('enabled'::text,worker_value,lease_token_value) OR schedule_row.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='schedule lease missing';END IF;
 IF outcome_value='advanced' AND (run_row.sync_id IS NULL OR run_row.scheduled_for IS DISTINCT FROM schedule_row.next_run_at OR run_row.completed_at IS NOT NULL) THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='scheduled sync required';END IF;
 result:=zasp_discovery_complete_schedule(organization_value,workspace_value,environment_value,schedule_value,worker_value,lease_token_value,outcome_value,next_run_value);
 IF outcome_value='advanced' THEN
  UPDATE zasp_discovery_schedule_runs SET completed_at=clock_timestamp(),completion_digest=digest_value,completion_result=result WHERE (organization_id,workspace_id,environment_id,schedule_id,sync_id)=(organization_value,workspace_value,environment_value,schedule_value,run_row.sync_id);
 END IF;
 RETURN result;
END $complete$;

CREATE OR REPLACE FUNCTION public.zasp_execution_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $compatibility$
 SELECT COALESCE(expected_checksum='355815b171d2659421a55eed5d364b8aa5661e76798fd39957b13c399d0dfd52' AND expected_fingerprint='6a3a830ff7e43a220be6e0658a6262ed92c8c0165c803b34319acb0e0ed6cb9c' AND public.zasp_discovery_schedule_replay_guard(),false)
$compatibility$;
CREATE OR REPLACE FUNCTION public.zasp_execution_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $compatibility$
 SELECT public.zasp_discovery_schedule_replay_guard()
$compatibility$;

CREATE FUNCTION public.zasp_discovery_schedule_replay_function_identity(value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT replace(replace(pg_get_functiondef(value),'-- compiled schedule replay checksum','<compiled-checksum>'),'-- compiled schedule replay fingerprint','<compiled-fingerprint>')
$identity$;
CREATE FUNCTION public.zasp_discovery_schedule_replay_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','webhook',public.zasp_sa_webhook_live_fingerprint())
 UNION ALL SELECT concat_ws('|','execution',public.zasp_execution_live_fingerprint())
 UNION ALL SELECT concat_ws('|','saved',signature,definition,owner_name,acl::text) FROM zasp_schedule_replay_prior.functions
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_schedule_replay_prior'
 UNION ALL SELECT concat_ws('|','function',n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_discovery_schedule_replay_function_identity(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='zasp_schedule_replay_prior' OR p.oid IN(SELECT signature::regprocedure FROM zasp_schedule_replay_prior.functions) OR n.nspname='public' AND starts_with(p.proname,'zasp_discovery_schedule_replay_')
 UNION ALL SELECT concat_ws('|','table',n.nspname,c.relname,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND c.relkind='r'
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE (n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass) AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='zasp_schedule_replay_prior' OR c.oid='public.zasp_discovery_schedule_runs'::regclass
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_discovery_schedule_replay_security_ready() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $security$
 SELECT EXISTS(SELECT 1 FROM pg_class WHERE oid='public.zasp_discovery_schedule_runs'::regclass AND relowner='zasp_discovery_authority'::regrole AND relrowsecurity AND relforcerowsecurity)
 AND NOT EXISTS(SELECT 1 FROM public.zasp_discovery_execution_principals b JOIN pg_roles r ON r.rolname=b.principal_name WHERE NOT r.rolcanlogin OR NOT r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR NOT pg_has_role(r.oid,b.authority_role,'MEMBER'))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles role_value ON role_value.oid=m.roleid JOIN pg_roles member_value ON member_value.oid=m.member WHERE role_value.rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker') AND NOT(member_value.rolname='zasp_discovery_authority' AND m.admin_option OR NOT m.admin_option AND EXISTS(SELECT 1 FROM public.zasp_discovery_execution_principals b WHERE b.principal_name=member_value.rolname AND b.authority_role=role_value.rolname)))
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles member_value ON member_value.oid=m.member WHERE member_value.rolname IN('zasp_discovery_scheduler','zasp_projection_risk_worker','zasp_projection_graph_worker','zasp_projection_search_worker'))
$security$;
CREATE FUNCTION public.zasp_discovery_schedule_replay_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- compiled schedule replay checksum' AND expected_fingerprint='-- compiled schedule replay fingerprint'
 AND (SELECT count(*)=60 FROM public.zasp_schema_versions) AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>60)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=60 AND name='production_discovery_schedule_replay' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_discovery_schedule_replay_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_discovery_schedule_replay_fingerprint' AND value=expected_fingerprint)
 AND zasp_schedule_replay_prior.predecessor_ready('-- schedule replay predecessor checksum','-- schedule replay predecessor fingerprint')
 AND public.zasp_discovery_schedule_replay_security_ready()
 AND public.zasp_discovery_schedule_replay_live_fingerprint()=expected_fingerprint,false)
$ready$;
CREATE FUNCTION public.zasp_discovery_schedule_replay_guard() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $guard$
 SELECT public.zasp_discovery_schedule_replay_readiness('-- compiled schedule replay checksum','-- compiled schedule replay fingerprint')
$guard$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_discovery_schedule_replay_') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',p);
 END LOOP;
END $owners$;
GRANT EXECUTE ON FUNCTION public.zasp_discovery_schedule_replay_readiness(text,text) TO zasp_discovery_scheduler;
SET LOCAL check_function_bodies=on;
