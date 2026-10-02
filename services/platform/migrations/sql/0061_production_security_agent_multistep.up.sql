-- Unpublished persistence candidate. No version61 registration or runtime grants.
SET LOCAL lock_timeout='3s';
SELECT pg_advisory_xact_lock(hashtextextended('zasp-schema-migrations',0));
DO $guard$
BEGIN
 IF NOT public.zasp_discovery_schedule_replay_readiness('-- multistep predecessor checksum','-- multistep predecessor fingerprint') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep exact predecessor unavailable';
 END IF;
END $guard$;

-- The predecessor fingerprints the shared metadata table. Candidate identity
-- lives separately so even an unpublished installation leaves release60 exact.
CREATE TABLE public.zasp_sa_multistep_metadata (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 checksum text NOT NULL CHECK(checksum~'^[a-f0-9]{64}$'),
 fingerprint text NOT NULL CHECK(fingerprint~'^[a-f0-9]{64}$')
);
ALTER TABLE public.zasp_sa_multistep_metadata OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_sa_multistep_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_sa_multistep_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY authority ON public.zasp_sa_multistep_metadata USING(current_user='zasp_discovery_authority') WITH CHECK(current_user='zasp_discovery_authority');
REVOKE ALL ON public.zasp_sa_multistep_metadata FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker;

CREATE TABLE public.zasp_sa_multistep_definitions (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 definition_id text NOT NULL, definition_version bigint NOT NULL CHECK(definition_version>0),
 contract_version integer NOT NULL DEFAULT 61 CHECK(contract_version=61),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id) REFERENCES public.zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id)
);
CREATE TABLE public.zasp_sa_multistep_runs (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, definition_id text NOT NULL, definition_version bigint NOT NULL,
 plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id),
 UNIQUE(organization_id,workspace_id,environment_id,run_id,plan_hash),
 FOREIGN KEY(organization_id,workspace_id,environment_id,definition_id,definition_version) REFERENCES public.zasp_sa_multistep_definitions(organization_id,workspace_id,environment_id,definition_id,definition_version),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id) REFERENCES public.zasp_security_agent_plans(organization_id,workspace_id,environment_id,run_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,plan_hash) REFERENCES public.zasp_security_agent_plans(organization_id,workspace_id,environment_id,plan_hash)
);
CREATE TABLE public.zasp_sa_multistep_dependencies (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),
 step_id text NOT NULL, step_index integer NOT NULL CHECK(step_index=1),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 predecessor_step_id text NOT NULL, predecessor_step_index integer NOT NULL CHECK(predecessor_step_index=0),
 predecessor_input_digest bytea NOT NULL CHECK(octet_length(predecessor_input_digest)=32),
 required_receipt_kind text NOT NULL CHECK(required_receipt_kind='temporary_policy_applied.v1'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 CHECK(step_index=predecessor_step_index+1 AND step_id<>predecessor_step_id),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 UNIQUE(organization_id,workspace_id,environment_id,run_id,step_index),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,plan_hash) REFERENCES public.zasp_sa_multistep_runs(organization_id,workspace_id,environment_id,run_id,plan_hash),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,predecessor_step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id)
);

-- Closed typed bodies. Strings in an effect's mutable state column are never
-- completion authority. Consumers must still verify current control activity.
CREATE FUNCTION public.zasp_sa_multistep_body_valid(kind text,body jsonb) RETURNS boolean
 LANGUAGE plpgsql IMMUTABLE SET search_path TO pg_catalog,public AS $body$
DECLARE key text; keys text[];
BEGIN
 IF body IS NULL OR jsonb_typeof(body)<>'object' OR octet_length(body::text)>8192 THEN RETURN false;END IF;
 IF kind='temporary_policy_applied.v1' THEN
  keys:=ARRAY['deployment_id','control_id','control_version','outcome_id','applied_at','expires_at'];
  IF NOT (body ?& keys) OR body-keys<>'{}'::jsonb THEN RETURN false;END IF;
  FOREACH key IN ARRAY ARRAY['deployment_id','control_id','outcome_id'] LOOP
   IF jsonb_typeof(body->key) IS DISTINCT FROM 'string' OR length(btrim(body->>key)) NOT BETWEEN 1 AND 128 THEN RETURN false;END IF;
  END LOOP;
  IF jsonb_typeof(body->'control_version') IS DISTINCT FROM 'number' OR (body->>'control_version')!~'^[1-9][0-9]{0,15}$' THEN RETURN false;END IF;
  FOREACH key IN ARRAY ARRAY['applied_at','expires_at'] LOOP
   IF jsonb_typeof(body->key) IS DISTINCT FROM 'string' OR (body->>key)!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$' THEN RETURN false;END IF;
  END LOOP;
  RETURN (body->>'expires_at')::timestamptz>(body->>'applied_at')::timestamptz;
 ELSIF kind='existing_test_settled.v1' THEN
  keys:=ARRAY['invocation_id','snapshot_digest','proof_digest','settlement_generation','outcome'];
  RETURN COALESCE(body ?& keys AND body-keys='{}'::jsonb
   AND jsonb_typeof(body->'invocation_id')='string' AND length(btrim(body->>'invocation_id')) BETWEEN 1 AND 128
   AND jsonb_typeof(body->'snapshot_digest')='string' AND (body->>'snapshot_digest')~'^[a-f0-9]{64}$'
   AND jsonb_typeof(body->'proof_digest')='string' AND (body->>'proof_digest')~'^[a-f0-9]{64}$'
   AND jsonb_typeof(body->'settlement_generation')='number' AND (body->>'settlement_generation')~'^[1-9][0-9]{0,15}$'
   AND body->>'outcome' IN('not_reproduced','reproduced','unknown'),false);
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $body$;
CREATE TABLE public.zasp_sa_multistep_receipts (
 organization_id text NOT NULL, workspace_id text NOT NULL, environment_id text NOT NULL,
 run_id text NOT NULL, plan_hash bytea NOT NULL CHECK(octet_length(plan_hash)=32),
 step_id text NOT NULL, action_key text NOT NULL,
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 receipt_kind text NOT NULL, receipt_version integer NOT NULL CHECK(receipt_version=1),
 body jsonb NOT NULL CHECK(public.zasp_sa_multistep_body_valid(receipt_kind,body)),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 CHECK((action_key,receipt_kind) IN(('create_temporary_policy','temporary_policy_applied.v1'),('run_test','existing_test_settled.v1'))),
 PRIMARY KEY(organization_id,workspace_id,environment_id,run_id,step_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,plan_hash) REFERENCES public.zasp_sa_multistep_runs(organization_id,workspace_id,environment_id,run_id,plan_hash),
 FOREIGN KEY(organization_id,workspace_id,environment_id,run_id,step_id) REFERENCES public.zasp_security_agent_steps(organization_id,workspace_id,environment_id,run_id,step_id)
);
CREATE INDEX zasp_sa_multistep_dependencies_predecessor_idx ON public.zasp_sa_multistep_dependencies(organization_id,workspace_id,environment_id,run_id,predecessor_step_id,required_receipt_kind);
CREATE INDEX zasp_sa_multistep_receipts_kind_idx ON public.zasp_sa_multistep_receipts(organization_id,workspace_id,environment_id,run_id,receipt_kind);

-- Legacy tables lack composite keys including digests. Do not add indexes or
-- triggers to fingerprinted release60 objects. Lock and validate exact tuples
-- on insertion; the new rows are append-only and never follow mutable values.
CREATE FUNCTION public.zasp_sa_multistep_bind() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $bind$
DECLARE p public.zasp_security_agent_plans%ROWTYPE; r public.zasp_security_agent_runs%ROWTYPE; s public.zasp_security_agent_steps%ROWTYPE; previous public.zasp_security_agent_steps%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep contract is immutable';END IF;
 IF TG_TABLE_NAME='zasp_sa_multistep_definitions' THEN
  PERFORM 1 FROM public.zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id,definition_id,version)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.definition_id,NEW.definition_version) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep definition binding rejected';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO r FROM public.zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) FOR SHARE;
 SELECT * INTO p FROM public.zasp_security_agent_plans WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) FOR SHARE;
 IF r.plan_hash IS DISTINCT FROM NEW.plan_hash OR p.plan_hash IS DISTINCT FROM NEW.plan_hash OR (p.definition_id,p.definition_version) IS DISTINCT FROM (r.definition_id,r.definition_version) THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep plan binding rejected';END IF;
 IF TG_TABLE_NAME='zasp_sa_multistep_runs' THEN
  IF (NEW.definition_id,NEW.definition_version) IS DISTINCT FROM (r.definition_id,r.definition_version) THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep run binding rejected';END IF;
  RETURN NEW;
 END IF;
 -- Stable step ordering prevents dependent/predecessor insert lock inversions.
 PERFORM 1 FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id) ORDER BY step_index FOR SHARE;
 SELECT * INTO s FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id,NEW.step_id);
 IF s.input_digest IS DISTINCT FROM NEW.input_digest THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep step binding rejected';END IF;
 IF TG_TABLE_NAME='zasp_sa_multistep_dependencies' THEN
  SELECT * INTO previous FROM public.zasp_security_agent_steps WHERE (organization_id,workspace_id,environment_id,run_id,step_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.run_id,NEW.predecessor_step_id);
  IF (s.step_index,s.action_key,previous.step_index,previous.action_key,previous.input_digest) IS DISTINCT FROM (NEW.step_index,'run_test'::text,NEW.predecessor_step_index,'create_temporary_policy'::text,NEW.predecessor_input_digest) THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep predecessor binding rejected';END IF;
 ELSE
  IF s.action_key IS DISTINCT FROM NEW.action_key OR (s.step_index,NEW.action_key) NOT IN((0,'create_temporary_policy'),(1,'run_test')) THEN RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='multistep receipt binding rejected';END IF;
 END IF;
 RETURN NEW;
END $bind$;

DO $tables$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['zasp_sa_multistep_definitions','zasp_sa_multistep_runs','zasp_sa_multistep_dependencies','zasp_sa_multistep_receipts'] LOOP
  EXECUTE format('ALTER TABLE public.%I OWNER TO zasp_discovery_authority',name);
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY authority ON public.%I USING(current_user=''zasp_discovery_authority'') WITH CHECK(current_user=''zasp_discovery_authority'')',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',name);
  EXECUTE format('CREATE TRIGGER immutable_binding BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.zasp_sa_multistep_bind()',name);
  EXECUTE format('CREATE TRIGGER immutable_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.zasp_sa_multistep_bind()',name);
 END LOOP;
END $tables$;

CREATE FUNCTION public.zasp_sa_multistep_function_identity(value oid) RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $identity$
 SELECT replace(replace(pg_get_functiondef(value),'-- compiled multistep checksum','<compiled-checksum>'),'-- compiled multistep fingerprint','<compiled-fingerprint>')
$identity$;
CREATE FUNCTION public.zasp_sa_multistep_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog,public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),p.proowner::regrole::text,p.prosecdef,p.provolatile,p.proparallel,p.proisstrict,p.proleakproof,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),public.zasp_sa_multistep_function_identity(p.oid)) FROM pg_proc p WHERE p.pronamespace='public'::regnamespace AND starts_with(p.proname,'zasp_sa_multistep_')
 UNION ALL SELECT concat_ws('|','table',c.relname,c.relkind,c.relpersistence,c.relowner::regrole::text,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','v','m','p','S')
 UNION ALL SELECT concat_ws('|','column',c.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated,a.attcollation::regcollation::text,COALESCE(pg_get_expr(d.adbin,d.adrelid),''),COALESCE(a.attacl::text,'')) FROM pg_class c JOIN pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum) WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_') AND c.relkind IN('r','p') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL SELECT concat_ws('|','constraint',c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 UNION ALL SELECT concat_ws('|','policy',c.relname,p.polname,p.polcmd,p.polpermissive,p.polroles::regrole[]::text,pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 UNION ALL SELECT concat_ws('|','index',c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,i.indislive) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid WHERE c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 UNION ALL SELECT concat_ws('|','trigger',c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE NOT t.tgisinternal AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 -- FK trigger names contain installation-specific OIDs. Bind their constraint,
 -- both relations, function, event flags and enabled state, on both FK sides.
 UNION ALL SELECT concat_ws('|','foreign-key-trigger',k.conrelid::regclass::text,k.conname,k.confrelid::regclass::text,t.tgrelid::regclass::text,t.tgconstrrelid::regclass::text,t.tgfoid::regprocedure::text,t.tgtype,t.tgenabled,t.tgdeferrable,t.tginitdeferred,t.tgnargs,encode(t.tgargs,'hex'),t.tgattr::text,COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')) FROM pg_trigger t JOIN pg_constraint k ON k.oid=t.tgconstraint JOIN pg_class c ON c.oid=k.conrelid WHERE t.tgisinternal AND k.contype='f' AND c.relnamespace='public'::regnamespace AND starts_with(c.relname,'zasp_sa_multistep_')
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_sa_multistep_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog,public AS $ready$
 SELECT COALESCE(expected_checksum='-- compiled multistep checksum' AND expected_fingerprint='-- compiled multistep fingerprint'
 AND public.zasp_discovery_schedule_replay_readiness('-- multistep predecessor checksum','-- multistep predecessor fingerprint')
 AND EXISTS(SELECT 1 FROM public.zasp_sa_multistep_metadata WHERE singleton AND checksum=expected_checksum AND fingerprint=expected_fingerprint)
 AND public.zasp_sa_multistep_live_fingerprint()=expected_fingerprint,false)
$ready$;

-- SECURITY DEFINER makes rollback inspect every tenant even for a migrator
-- subject to forced RLS. Lock all evidence sources before making the decision.
CREATE FUNCTION public.zasp_sa_multistep_assert_unused() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog,public AS $unused$
BEGIN
 LOCK TABLE public.zasp_security_agent_definitions,public.zasp_security_agent_definition_versions,public.zasp_security_agent_runs,public.zasp_security_agent_plans,public.zasp_security_agent_steps,public.zasp_security_agent_effects,public.zasp_security_agent_audit,public.zasp_sa_multistep_metadata,public.zasp_sa_multistep_definitions,public.zasp_sa_multistep_runs,public.zasp_sa_multistep_dependencies,public.zasp_sa_multistep_receipts IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM public.zasp_sa_multistep_definitions) OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_runs) OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_dependencies) OR EXISTS(SELECT 1 FROM public.zasp_sa_multistep_receipts)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_steps WHERE step_index>0)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_plans WHERE CASE WHEN jsonb_typeof(plan->'steps')='array' THEN jsonb_array_length(plan->'steps')>1 ELSE false END)
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definitions WHERE body->>'max_steps'~'^([2-9]|[1-9][0-9]+)$')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_definition_versions WHERE definition->>'max_steps'~'^([2-9]|[1-9][0-9]+)$')
 OR EXISTS(SELECT 1 FROM public.zasp_security_agent_audit WHERE body->>'contract_version'='61')
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='multistep durable work or evidence retained';END IF;
END $unused$;
DO $owners$
DECLARE p regprocedure;
BEGIN
 FOR p IN SELECT oid::regprocedure FROM pg_proc WHERE pronamespace='public'::regnamespace AND starts_with(proname,'zasp_sa_multistep_') LOOP
  EXECUTE format('ALTER FUNCTION %s OWNER TO zasp_discovery_authority',p);
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,zasp_security_agent_api,zasp_security_agent_worker,zasp_security_agent_action_worker',p);
 END LOOP;
END $owners$;
INSERT INTO public.zasp_sa_multistep_metadata(singleton,checksum,fingerprint) VALUES(true,'-- compiled multistep checksum','-- compiled multistep fingerprint');
