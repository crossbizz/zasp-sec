DO $guard$
BEGIN
 IF NOT public.zasp_production_runtime_session_evidence_readiness((SELECT checksum FROM public.zasp_schema_versions WHERE version=44),(SELECT value FROM public.zasp_schema_metadata WHERE key='production_runtime_session_evidence_fingerprint')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enrollment pairing prerequisite rejected';
 END IF;
END
$guard$;

-- Serialize installation/backfill with enrollment and batch mutations.
LOCK TABLE public.zasp_sensors,public.zasp_runtime_batch_authorities IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE public.zasp_sensors ADD CONSTRAINT zasp_sensor_kind_identity_v45 UNIQUE(organization_id,workspace_id,environment_id,id,kind);
ALTER TABLE public.zasp_runtime_batch_authorities ADD CONSTRAINT zasp_runtime_batch_source_identity_v45 UNIQUE(organization_id,workspace_id,environment_id,batch_id,batch_generation,sensor_id,source_kind);

CREATE TABLE public.zasp_runtime_sensor_pairings (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 sensor_id text NOT NULL,runtime_sensor_id text NOT NULL,
 source_kind text NOT NULL DEFAULT 'otlp' CHECK(source_kind='otlp'),runtime_kind text NOT NULL DEFAULT 'tetragon' CHECK(runtime_kind='tetragon'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,sensor_id),CHECK(sensor_id<>runtime_sensor_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,sensor_id,source_kind) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id,kind) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,runtime_sensor_id,runtime_kind) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id,kind) ON DELETE RESTRICT
);
CREATE TABLE public.zasp_runtime_batch_domains (
 organization_id text NOT NULL,workspace_id text NOT NULL,environment_id text NOT NULL,
 batch_id text NOT NULL,generation bigint NOT NULL CHECK(generation>0),source_sensor_id text NOT NULL,source_kind text NOT NULL CHECK(source_kind IN('tetragon','otlp')),
 runtime_sensor_id text,runtime_kind text NOT NULL DEFAULT 'tetragon' CHECK(runtime_kind='tetragon'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(organization_id,workspace_id,environment_id,batch_id),
 CHECK(source_kind<>'tetragon' OR runtime_sensor_id IS NOT DISTINCT FROM source_sensor_id),
 CHECK(source_kind<>'otlp' OR runtime_sensor_id IS DISTINCT FROM source_sensor_id),
 FOREIGN KEY(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind) REFERENCES public.zasp_runtime_batch_authorities(organization_id,workspace_id,environment_id,batch_id,batch_generation,sensor_id,source_kind) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,source_sensor_id,source_kind) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id,kind) ON DELETE RESTRICT,
 FOREIGN KEY(organization_id,workspace_id,environment_id,runtime_sensor_id,runtime_kind) REFERENCES public.zasp_sensors(organization_id,workspace_id,environment_id,id,kind) ON DELETE RESTRICT
);
ALTER TABLE public.zasp_runtime_sensor_pairings OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_batch_domains OWNER TO zasp_discovery_authority;
ALTER TABLE public.zasp_runtime_sensor_pairings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_sensor_pairings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_batch_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.zasp_runtime_batch_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY zasp_runtime_sensor_pairings_authority ON public.zasp_runtime_sensor_pairings TO zasp_discovery_authority USING(true) WITH CHECK(true);
CREATE POLICY zasp_runtime_batch_domains_authority ON public.zasp_runtime_batch_domains TO zasp_discovery_authority USING(true) WITH CHECK(true);
REVOKE ALL ON TABLE public.zasp_runtime_sensor_pairings,public.zasp_runtime_batch_domains FROM PUBLIC;

CREATE FUNCTION public.zasp_runtime_pairing_immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $immutable$
BEGIN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enrollment provenance is immutable';
END
$immutable$;
ALTER FUNCTION public.zasp_runtime_pairing_immutable() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_pairing_immutable() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_sensor_pairings_immutable BEFORE UPDATE OR DELETE ON public.zasp_runtime_sensor_pairings FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_pairing_immutable();
CREATE TRIGGER zasp_runtime_batch_domains_immutable BEFORE UPDATE OR DELETE ON public.zasp_runtime_batch_domains FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_pairing_immutable();

CREATE FUNCTION public.zasp_runtime_bind_batch_domain() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $binding$
DECLARE runtime_value text;
BEGIN
 IF NEW.source_kind='tetragon' THEN runtime_value:=NEW.sensor_id;
 ELSIF NEW.source_kind='otlp' THEN
  SELECT runtime_sensor_id INTO runtime_value FROM zasp_runtime_sensor_pairings WHERE (organization_id,workspace_id,environment_id,sensor_id)=(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.sensor_id);
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='runtime batch source rejected';END IF;
 INSERT INTO zasp_runtime_batch_domains(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind,runtime_sensor_id)
 VALUES(NEW.organization_id,NEW.workspace_id,NEW.environment_id,NEW.batch_id,NEW.batch_generation,NEW.sensor_id,NEW.source_kind,runtime_value);
 RETURN NEW;
END
$binding$;
ALTER FUNCTION public.zasp_runtime_bind_batch_domain() OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_bind_batch_domain() FROM PUBLIC;
CREATE TRIGGER zasp_runtime_batch_domain_insert AFTER INSERT ON public.zasp_runtime_batch_authorities FOR EACH ROW EXECUTE FUNCTION public.zasp_runtime_bind_batch_domain();
-- No historical OTLP enrollment is implicitly paired. The type-bound foreign
-- keys also reject any inconsistent historical source authority.
INSERT INTO public.zasp_runtime_batch_domains(organization_id,workspace_id,environment_id,batch_id,generation,source_sensor_id,source_kind,runtime_sensor_id)
SELECT organization_id,workspace_id,environment_id,batch_id,batch_generation,sensor_id,source_kind,CASE WHEN source_kind='tetragon' THEN sensor_id ELSE NULL END FROM public.zasp_runtime_batch_authorities;

ALTER FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text) RENAME TO zasp_runtime_public_sensor_value_v44;
CREATE FUNCTION public.zasp_runtime_public_sensor_value(organization_value text,workspace_value text,environment_value text,sensor_value text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $value$
 SELECT zasp_runtime_public_sensor_value_v44(organization_value,workspace_value,environment_value,sensor_value) || COALESCE((SELECT jsonb_build_object('runtime_sensor_id',runtime_sensor_id) FROM zasp_runtime_sensor_pairings WHERE (organization_id,workspace_id,environment_id,sensor_id)=(organization_value,workspace_value,environment_value,sensor_value)),'{}'::jsonb)
$value$;
ALTER FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_public_sensor_value(text,text,text,text) FROM PUBLIC;

ALTER FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) RENAME TO zasp_runtime_public_create_sensor_v44;
REVOKE ALL ON FUNCTION public.zasp_runtime_public_create_sensor_v44(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) FROM PUBLIC,zasp_discovery_api;
CREATE FUNCTION public.zasp_runtime_public_create_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,name_value text,kind_value text,mode_value text,idempotency_value text,request_digest_value bytea,token_value text,generation_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz,runtime_sensor_value text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO pg_catalog, public AS $create$
DECLARE prior_value zasp_runtime_sensor_mutations%ROWTYPE;result_value jsonb;stored_runtime text;
BEGIN
 IF runtime_sensor_value IS NOT NULL AND NOT COALESCE(kind_value='otlp' AND zasp_valid_product_id(runtime_sensor_value) AND runtime_sensor_value<>sensor_value,false) THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='sensor pairing rejected';END IF;
 IF runtime_sensor_value IS NOT NULL AND NOT COALESCE(zasp_discovery_principal_ready('zasp_discovery_api') AND EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? 'manage_workflows'),false) THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sensor pairing authority rejected';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(chr(31),organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value),0));
 IF runtime_sensor_value IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? 'manage_workflows') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sensor pairing authority rejected';END IF;
 SELECT * INTO prior_value FROM zasp_runtime_sensor_mutations WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key)=(organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value) FOR UPDATE;
 IF FOUND THEN
  -- Receipt row locking can independently wait after the advisory lock.
  IF runtime_sensor_value IS NOT NULL AND NOT EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? 'manage_workflows') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sensor pairing authority rejected';END IF;
  SELECT runtime_sensor_id INTO stored_runtime FROM zasp_runtime_sensor_pairings WHERE (organization_id,workspace_id,environment_id,sensor_id)=(organization_value,workspace_value,environment_value,prior_value.sensor_id);
  IF prior_value.request_digest IS DISTINCT FROM request_digest_value OR stored_runtime IS DISTINCT FROM runtime_sensor_value
   OR prior_value.result#>>'{body,id}' IS DISTINCT FROM prior_value.sensor_id OR prior_value.result#>>'{body,runtime_sensor_id}' IS DISTINCT FROM stored_runtime
   OR prior_value.result#>>'{body,name}' IS DISTINCT FROM name_value OR prior_value.result#>>'{body,kind}' IS DISTINCT FROM kind_value OR prior_value.result#>>'{body,mode}' IS DISTINCT FROM mode_value THEN
   RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor pairing replay conflict';
  END IF;
  RETURN jsonb_set(prior_value.result,'{replayed}','true'::jsonb);
 END IF;
 IF runtime_sensor_value IS NOT NULL THEN
  -- FOR SHARE conflicts with status updates; KEY SHARE would not fence revoke.
  PERFORM 1 FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id,id)=(organization_value,workspace_value,environment_value,runtime_sensor_value) AND kind='tetragon' AND state='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='runtime sensor pairing anchor missing';END IF;
  -- Permission may have changed while waiting for the anchor or idempotency lock.
  IF NOT EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? 'manage_workflows') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sensor pairing authority rejected';END IF;
 END IF;
 result_value:=zasp_runtime_public_create_sensor_v44(organization_value,workspace_value,environment_value,principal_value,sensor_value,name_value,kind_value,mode_value,idempotency_value,request_digest_value,token_value,generation_value,locator_digest_value,salt_value,token_hash_value,expires_value);
 IF result_value->>'replayed' IS DISTINCT FROM 'false' OR result_value#>>'{body,id}' IS DISTINCT FROM sensor_value THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor pairing creation conflict';END IF;
 IF runtime_sensor_value IS NOT NULL THEN
  -- The legacy creation path may have waited on credential uniqueness locks.
  IF NOT EXISTS(SELECT 1 FROM zasp_identity_admin_effective_scopes(principal_value,organization_value) effective WHERE (effective.organization_id,effective.workspace_id,effective.environment_id)=(organization_value,workspace_value,environment_value) AND effective.permissions ? 'manage_workflows') THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='sensor pairing authority rejected';END IF;
  INSERT INTO zasp_runtime_sensor_pairings(organization_id,workspace_id,environment_id,sensor_id,runtime_sensor_id) VALUES(organization_value,workspace_value,environment_value,sensor_value,runtime_sensor_value);
  result_value:=jsonb_set(result_value,'{body,runtime_sensor_id}',to_jsonb(runtime_sensor_value));
  UPDATE zasp_runtime_sensor_mutations SET result=result_value WHERE (organization_id,workspace_id,environment_id,principal_id,operation,idempotency_key,sensor_id)=(organization_value,workspace_value,environment_value,principal_value,'createSensorEnrollment',idempotency_value,sensor_value) AND request_digest=request_digest_value;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23505',MESSAGE='sensor pairing receipt missing';END IF;
 END IF;
 RETURN result_value;
END
$create$;
CREATE FUNCTION public.zasp_runtime_public_create_sensor(organization_value text,workspace_value text,environment_value text,principal_value text,sensor_value text,name_value text,kind_value text,mode_value text,idempotency_value text,request_digest_value bytea,token_value text,generation_value bigint,locator_digest_value bytea,salt_value bytea,token_hash_value bytea,expires_value timestamptz) RETURNS jsonb LANGUAGE sql SECURITY DEFINER SET search_path TO pg_catalog, public AS $legacy$
 SELECT zasp_runtime_public_create_sensor(organization_value,workspace_value,environment_value,principal_value,sensor_value,name_value,kind_value,mode_value,idempotency_value,request_digest_value,token_value,generation_value,locator_digest_value,salt_value,token_hash_value,expires_value,NULL::text)
$legacy$;
ALTER FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz,text) OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz,text),public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz,text),public.zasp_runtime_public_create_sensor(text,text,text,text,text,text,text,text,text,bytea,text,bigint,bytea,bytea,bytea,timestamptz) TO zasp_discovery_api;

DO $compatibility$
DECLARE definition text;prior text;function_name text;
BEGIN
 FOREACH function_name IN ARRAY ARRAY['public.zasp_workflow_mutate(text,text,text,text,text,text,text,text,text,bigint,jsonb,jsonb,text,text,text)','public.zasp_risk_mutate(text,text,text,text,text,text,text,bigint,text,text,text,text,text)','public.zasp_production_security_agent_attack_path_security_ready()','public.zasp_production_workflow_compatibility_security_ready()'] LOOP
  SELECT pg_get_functiondef(function_name::regprocedure) INTO STRICT definition;prior:=definition;
  definition:=replace(replace(replace(definition,'later_release."version" > 44','later_release."version" > 45'),'later."version">44','later."version">45'),'later."version" > 44','later."version" > 45');
  IF definition=prior THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='runtime enrollment compatibility rejected';END IF;
  EXECUTE definition;
 END LOOP;
END
$compatibility$;

CREATE FUNCTION public.zasp_production_runtime_enrollment_pairing_security_ready() RETURNS boolean LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $security$
 SELECT zasp_production_runtime_session_evidence_security_ready()
 AND (SELECT count(*)=2 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains') AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') AND c.relrowsecurity AND c.relforcerowsecurity
  AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE acl.grantee<>c.relowner))
 AND (SELECT count(*)=3 FROM pg_trigger WHERE tgname IN('zasp_runtime_sensor_pairings_immutable','zasp_runtime_batch_domains_immutable','zasp_runtime_batch_domain_insert') AND tgenabled='O' AND NOT tgisinternal)
 AND (SELECT count(*)=2 FROM pg_constraint WHERE conname IN('zasp_sensor_kind_identity_v45','zasp_runtime_batch_source_identity_v45') AND convalidated)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN('zasp_runtime_pairing_immutable','zasp_runtime_bind_batch_domain','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_value_v44','zasp_runtime_public_create_sensor','zasp_runtime_public_create_sensor_v44')
  AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_authority') OR NOT p.prosecdef OR NOT COALESCE(p.proconfig,'{}') @> ARRAY['search_path=pg_catalog, public']
   OR EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) acl WHERE acl.privilege_type='EXECUTE' AND acl.grantee<>p.proowner AND NOT(p.proname='zasp_runtime_public_create_sensor' AND acl.grantee=(SELECT oid FROM pg_roles WHERE rolname='zasp_discovery_api')))))
$security$;
CREATE FUNCTION public.zasp_production_runtime_enrollment_pairing_live_fingerprint() RETURNS text LANGUAGE sql STABLE SET search_path TO pg_catalog, public AS $fingerprint$
 WITH identities(value) AS (
 SELECT concat_ws('|','prior',zasp_production_runtime_session_evidence_live_fingerprint())
 UNION ALL SELECT concat_ws('|','function',p.proname,pg_get_function_identity_arguments(p.oid),r.rolname,p.prosecdef,COALESCE(p.proconfig::text,''),COALESCE(p.proacl::text,''),pg_get_functiondef(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='public' AND p.proname IN('zasp_runtime_pairing_immutable','zasp_runtime_bind_batch_domain','zasp_runtime_public_sensor_value','zasp_runtime_public_sensor_value_v44','zasp_runtime_public_create_sensor','zasp_runtime_public_create_sensor_v44','zasp_production_runtime_enrollment_pairing_readiness','zasp_production_runtime_enrollment_pairing_security_ready')
 UNION ALL SELECT concat_ws('|','table',c.relname,r.rolname,c.relrowsecurity,c.relforcerowsecurity,COALESCE(c.relacl::text,'')) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relname IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
 UNION ALL SELECT concat_ws('|','column',table_name,column_name,data_type,is_nullable,COALESCE(column_default,'')) FROM information_schema.columns WHERE table_schema='public' AND table_name IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
 UNION ALL SELECT concat_ws('|','constraint',conrelid::regclass::text,conname,pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conrelid IN('public.zasp_runtime_sensor_pairings'::regclass,'public.zasp_runtime_batch_domains'::regclass) OR conname IN('zasp_sensor_kind_identity_v45','zasp_runtime_batch_source_identity_v45')
 UNION ALL SELECT concat_ws('|','policy',tablename,policyname,roles::text,cmd,qual,with_check) FROM pg_policies WHERE schemaname='public' AND tablename IN('zasp_runtime_sensor_pairings','zasp_runtime_batch_domains')
 UNION ALL SELECT concat_ws('|','trigger',tgname,tgenabled,pg_get_triggerdef(oid,true)) FROM pg_trigger WHERE tgname IN('zasp_runtime_sensor_pairings_immutable','zasp_runtime_batch_domains_immutable','zasp_runtime_batch_domain_insert') AND NOT tgisinternal
 ) SELECT encode(digest(convert_to(string_agg(value,E'\n' ORDER BY value),'UTF8'),'sha256'),'hex') FROM identities
$fingerprint$;
CREATE FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $readiness$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=45 AND name='production_runtime_enrollment_pairing' AND checksum=expected_checksum) AND NOT EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version>45) AND zasp_production_runtime_enrollment_pairing_security_ready() AND zasp_production_runtime_enrollment_pairing_live_fingerprint()=expected_fingerprint
$readiness$;
ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_security_ready() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_live_fingerprint() OWNER TO zasp_discovery_authority;
ALTER FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_enrollment_pairing_security_ready(),public.zasp_production_runtime_enrollment_pairing_live_fingerprint(),public.zasp_production_runtime_enrollment_pairing_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_enrollment_pairing_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;

ALTER FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) RENAME TO zasp_production_runtime_session_evidence_readiness_v44;
CREATE FUNCTION public.zasp_production_runtime_session_evidence_readiness(expected_checksum text,expected_fingerprint text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path TO pg_catalog, public AS $compatibility$
 SELECT expected_checksum ~ '^[a-f0-9]{64}$' AND expected_fingerprint ~ '^[a-f0-9]{64}$' AND EXISTS(SELECT 1 FROM zasp_schema_versions WHERE version=44 AND name='production_runtime_session_evidence' AND checksum=expected_checksum) AND EXISTS(SELECT 1 FROM zasp_schema_metadata WHERE key='production_runtime_session_evidence_fingerprint' AND value=expected_fingerprint) AND zasp_production_runtime_enrollment_pairing_readiness((SELECT checksum FROM zasp_schema_versions WHERE version=45),(SELECT value FROM zasp_schema_metadata WHERE key='production_runtime_enrollment_pairing_fingerprint'))
$compatibility$;
ALTER FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.zasp_production_runtime_session_evidence_readiness(text,text) TO zasp_runtime_index_worker,zasp_runtime_coordinator,zasp_discovery_api;
INSERT INTO public.zasp_schema_metadata(key,value) VALUES('production_runtime_enrollment_pairing_fingerprint', 'db92341310fc79a716b87a224b902a2c10101f7e4a9f04ddbf0c3a7f487f3e3d');
