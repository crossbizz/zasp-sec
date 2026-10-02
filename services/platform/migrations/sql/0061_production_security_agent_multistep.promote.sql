-- Runner holds schema/evidence locks. Candidate installation is still exact60.
DO $guard$
BEGIN
 IF NOT public.zasp_sa_multistep_readiness('-- compiled multistep checksum','-- compiled multistep fingerprint') THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep candidate unavailable';END IF;
END $guard$;
CREATE SCHEMA zasp_sa_multistep_prior AUTHORIZATION zasp_discovery_authority;
REVOKE ALL ON SCHEMA zasp_sa_multistep_prior FROM PUBLIC;
CREATE TABLE zasp_sa_multistep_prior.functions(signature text PRIMARY KEY,definition text NOT NULL,owner_name text NOT NULL,acl jsonb NOT NULL);
ALTER TABLE zasp_sa_multistep_prior.functions OWNER TO zasp_discovery_authority;
REVOKE ALL ON zasp_sa_multistep_prior.functions FROM PUBLIC;
DO $ancestry$
DECLARE sig text;p pg_proc%ROWTYPE;d text;needle text;
BEGIN
 FOREACH sig IN ARRAY ARRAY[
 'zasp_sa_attack_lab_prior.predecessor_ready(text,text)',
 'zasp_sa_export_prior.predecessor_ready(text,text)',
 'zasp_sa_webhook_prior.predecessor_ready(text,text)',
 'zasp_schedule_replay_prior.predecessor_ready(text,text)',
 'zasp_sa_attack_lab_prior.audit_fingerprint()',
 'public.zasp_sa_multistep_readiness(text,text)',
 'public.zasp_sa_multistep_function_identity(oid)',
 'public.zasp_security_agent_budget_settle_planner(text,text,text,text,text,text,bigint,text,bytea,bigint,bigint,bigint,bigint)',
 'public.zasp_security_agent_decide_approval(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)',
 'public.zasp_security_agent_decide_approval_v22(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)',
 'public.zasp_security_agent_decide_approval_v23(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)',
 'public.zasp_security_agent_decide_approval_v24(text,text,text,text,text,text,bigint,text,timestamp with time zone,text,text,text)',
 'public.zasp_security_agent_expire_approvals_v28(text,integer)',
 'public.zasp_security_agent_claim_temporary_policy_effects(text,text,integer,integer)',
 'public.zasp_security_agent_heartbeat_temporary_policy_effect(text,text,text,text,text,text,text,integer)',
 'public.zasp_security_agent_execute_run(text,text,text,text,text,text,text,text)',
 'public.zasp_security_agent_execute_run_v21(text,text,text,text,text,text,text,text)',
 'public.zasp_security_agent_execute_run_v22(text,text,text,text,text,text,text,text)',
 'public.zasp_security_agent_execute_run_v23(text,text,text,text,text,text,text,text)',
 'public.zasp_security_agent_execute_run_v24(text,text,text,text,text,text,text,text)',
 'public.zasp_security_agent_finish_temporary_policy_effect(text,text,text,text,text,text,text,text,bytea,text,text)',
 'public.zasp_security_agent_store_temporary_policy_target(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)',
 'public.zasp_security_agent_store_temporary_policy_target_v27(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)',
 'public.zasp_policy_deployment_store_temporary_source(text,text,text,text,text,text,text,text,text,text,bigint,bigint,text,timestamp with time zone,timestamp with time zone,text,bytea,jsonb,bytea,bytea)',
 'public.zasp_sa_multistep_assert_unused()'] LOOP
  SELECT * INTO STRICT p FROM pg_proc WHERE oid=sig::regprocedure;
  INSERT INTO zasp_sa_multistep_prior.functions SELECT sig,pg_get_functiondef(p.oid),p.proowner::regrole::text,COALESCE((SELECT jsonb_agg(jsonb_build_object('grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END,'grantable',a.is_grantable) ORDER BY a.ordinality) FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) WITH ORDINALITY a WHERE a.privilege_type='EXECUTE'),'[]');
  d:=pg_get_functiondef(p.oid);
  IF strpos(sig,'predecessor_ready(')>0 THEN
   IF strpos(d,'count(*)=60')=0 OR strpos(d,'version>60')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep predecessor shape rejected';END IF;
   EXECUTE replace(replace(d,'count(*)=60','count(*)=61'),'version>60','version>61');
  ELSIF sig='zasp_sa_attack_lab_prior.audit_fingerprint()' THEN
   needle:='''production_discovery_schedule_replay_checksum'',''production_discovery_schedule_replay_fingerprint''';
   IF strpos(d,needle)=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep ancestry rejected';END IF;
   EXECUTE replace(d,needle,needle||',''production_security_agent_multistep_checksum'',''production_security_agent_multistep_fingerprint''');
  ELSIF sig='public.zasp_sa_multistep_assert_unused()' THEN
   IF strpos(d,'public.zasp_sa_multistep_receipts IN ACCESS EXCLUSIVE MODE')=0 OR strpos(d,'IF EXISTS(SELECT 1 FROM public.zasp_sa_multistep_definitions)')=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep evidence guard predecessor rejected';END IF;
   d:=replace(d,'public.zasp_sa_multistep_metadata,','');
   d:=replace(d,'public.zasp_sa_multistep_receipts IN ACCESS EXCLUSIVE MODE','public.zasp_sa_multistep_receipts,zasp_sa_multistep_prior.admissions,zasp_sa_multistep_prior.pricing_policies,zasp_sa_multistep_prior.pricing_accounts,zasp_sa_multistep_prior.pricing_mutations,zasp_sa_multistep_prior.planning_jobs IN ACCESS EXCLUSIVE MODE');
   EXECUTE replace(d,'IF EXISTS(SELECT 1 FROM public.zasp_sa_multistep_definitions)','IF EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.planning_jobs) OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.pricing_policies) OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.pricing_accounts) OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.pricing_mutations) OR EXISTS(SELECT 1 FROM zasp_sa_multistep_prior.admissions) OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_definitions)');
  END IF;
 END LOOP;
 -- Only the private chain understands61. Public60 readiness and guards are
 -- deliberately untouched, so old binaries cannot use an evolved schema.
 d:=pg_get_functiondef('public.zasp_discovery_schedule_replay_readiness(text,text)'::regprocedure);
 IF strpos(d,'count(*)=60')=0 OR strpos(d,'version>60')=0 OR strpos(d,'public.zasp_discovery_schedule_replay_live_fingerprint()=expected_fingerprint')=0 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep predecessor rejected';END IF;
 d:=replace(replace(d,'count(*)=60','count(*)=61'),'version>60','version>61');
 EXECUTE replace(replace(d,'FUNCTION public.zasp_discovery_schedule_replay_readiness(','FUNCTION zasp_sa_multistep_prior.predecessor_ready('),'public.zasp_discovery_schedule_replay_live_fingerprint()=expected_fingerprint','true');
 ALTER FUNCTION zasp_sa_multistep_prior.predecessor_ready(text,text) OWNER TO zasp_discovery_authority;
 REVOKE ALL ON FUNCTION zasp_sa_multistep_prior.predecessor_ready(text,text) FROM PUBLIC;
END $ancestry$;

CREATE OR REPLACE FUNCTION public.zasp_sa_multistep_function_identity(value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT replace(replace(replace(pg_get_functiondef(value),'-- compiled multistep checksum','<compiled-checksum>'),'-- compiled multistep fingerprint','<compiled-fingerprint>'),'-- registered multistep fingerprint','<registered-fingerprint>')
$identity$;

CREATE FUNCTION public.zasp_sa_multistep_registered_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','candidate',public.zasp_sa_multistep_live_fingerprint())
 UNION ALL SELECT concat_ws('|','predecessor',public.zasp_discovery_schedule_replay_live_fingerprint())
 UNION ALL SELECT concat_ws('|','saved',signature,replace(replace(definition,'-- compiled multistep checksum','<compiled-checksum>'),'-- compiled multistep fingerprint','<compiled-fingerprint>'),owner_name,acl::text) FROM zasp_sa_multistep_prior.functions
 UNION ALL SELECT concat_ws('|','legacy-approval-fence',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_decide_approval','zasp_security_agent_decide_approval_v22','zasp_security_agent_decide_approval_v23','zasp_security_agent_decide_approval_v24','zasp_security_agent_expire_approvals_v28')
 -- The unchanged private dispatch leaf is also bound, including its closed ACL.
 UNION ALL SELECT concat_ws('|','legacy-action-fence',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND p.proname IN('zasp_security_agent_claim_temporary_policy_effects','zasp_security_agent_heartbeat_temporary_policy_effect','zasp_security_agent_dispatch_temporary_policy_run','zasp_security_agent_finish_temporary_policy_effect','zasp_security_agent_store_temporary_policy_target','zasp_security_agent_store_temporary_policy_target_v27','zasp_policy_deployment_store_temporary_source','zasp_security_agent_execute_run','zasp_security_agent_execute_run_v21','zasp_security_agent_execute_run_v22','zasp_security_agent_execute_run_v23','zasp_security_agent_execute_run_v24')
 UNION ALL SELECT concat_ws('|','schema',nspname,nspowner::regrole::text,COALESCE(nspacl::text,'')) FROM pg_namespace WHERE nspname='zasp_sa_multistep_prior'
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_sa_multistep_function_identity(p.oid)) FROM pg_proc p WHERE p.pronamespace='zasp_sa_multistep_prior'::regnamespace
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','v','m','p','S')
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
 -- Admission FKs bind the budget/provider receipt and the immutable run. Bind
 -- both trigger sides without installation-specific generated trigger names.
 UNION ALL SELECT concat_ws('|','foreign-key-trigger',k.conrelid::regclass::text,k.conname,k.confrelid::regclass::text,t.tgrelid::regclass::text,t.tgconstrrelid::regclass::text,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgnargs,encode(t.tgargs,'hex'),t.tgattr::text,COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='zasp_sa_multistep_prior'::regnamespace
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='zasp_sa_multistep_prior'::regnamespace
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
ALTER FUNCTION public.zasp_sa_multistep_registered_live_fingerprint() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_sa_multistep_registered_live_fingerprint() FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.zasp_sa_multistep_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- compiled multistep checksum' AND expected_fingerprint='-- registered multistep fingerprint'
 AND (SELECT count(*)=61 FROM public.zasp_schema_versions) AND NOT EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version<1 OR version>61)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_versions WHERE version=61 AND name='production_security_agent_multistep' AND checksum=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_checksum' AND value=expected_checksum)
 AND EXISTS(SELECT 1 FROM public.zasp_schema_metadata WHERE key='production_security_agent_multistep_fingerprint' AND value=expected_fingerprint)
 AND to_regclass('public.zasp_sa_multistep_metadata') IS NULL
 AND zasp_sa_multistep_prior.predecessor_ready('-- multistep predecessor checksum','-- multistep predecessor fingerprint')
 AND public.zasp_sa_multistep_registered_live_fingerprint()=expected_fingerprint,false)
$ready$;
DROP TABLE public.zasp_sa_multistep_metadata;

-- registered multistep admission

-- registered multistep progression

-- registered multistep legacy actions

-- registered multistep application

-- registered multistep deployment

-- registered multistep test artifacts

-- registered multistep test
-- registered multistep test settlement
-- registered multistep cleanup
-- registered multistep cleanup deployment
-- registered multistep pricing
-- registered multistep planning
-- registered multistep orchestration
